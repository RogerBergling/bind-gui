/* BIND master-file (zone file) parser. */

import {
  ensureTrailingDot,
  isSubdomain,
  normalizeName,
  validateDomainName,
} from './names.js';
import { normalizeType, typeCode } from './types.js';
import { canonicalRdata, parseTTL, tokenizeFields, tokenValue } from './syntax.js';
import { normalizeNewlines } from '../utils.js';

const CLASS_NAMES = new Set(['IN', 'CH', 'HS', 'NONE', 'ANY']);
const MAX_GENERATE = 5000;

/**
 * Parse a BIND master file.
 *
 * @param {string} text
 * @param {object} [options]
 * @param {string} [options.origin] zone apex / initial $ORIGIN
 * @param {string} [options.file] display path
 * @param {number|null} [options.defaultTTL]
 * @param {(path: string, fromFile: string) => ({path: string, content: string}|null)} [options.resolveInclude]
 */
export function parseZone(text, options = {}) {
  const initialOrigin = ensureTrailingDot(options.origin || '.');
  const entryFile = options.file || 'zone.db';
  const records = [];
  const directives = [];
  const errors = [];
  const warnings = [];
  const includedFiles = new Set();
  let origin = initialOrigin;
  let defaultTTL = options.defaultTTL ?? null;
  let lastTTL = defaultTTL;
  let lastOwner = null;
  let generatedCount = 0;
  let currentFile = entryFile;

  function error(message, line) {
    errors.push({ message, line, file: currentFile });
  }

  function warn(message, line) {
    warnings.push({ message, line, file: currentFile });
  }

  function parseRecord(ownerValue, restTokens, line, extra = {}) {
    const owner = normalizeName(ownerValue, origin);
    const ownerValidation = validateDomainName(owner, { allowWildcard: true, allowUnderscore: true });
    if (!ownerValidation.valid) {
      for (const message of ownerValidation.errors) error(`Owner name: ${message}`, line);
    }
    for (const message of ownerValidation.warnings) warn(`Owner name: ${message}`, line);

    let index = 0;
    let ttl = null;
    let ttlExplicit = false;
    let recordClass = 'IN';
    let classExplicit = false;

    while (index < restTokens.length) {
      const value = tokenValue(restTokens[index]);
      const upper = value.toUpperCase();
      if (!ttlExplicit) {
        const candidate = parseTTL(value);
        if (candidate !== null) {
          ttl = candidate;
          ttlExplicit = true;
          index += 1;
          continue;
        }
      }
      if (!classExplicit && CLASS_NAMES.has(upper)) {
        recordClass = upper;
        classExplicit = true;
        index += 1;
        continue;
      }
      break;
    }

    if (index >= restTokens.length) {
      error('Record has no type or RDATA.', line);
      return null;
    }

    const rawType = tokenValue(restTokens[index]);
    const type = normalizeType(rawType);
    if (typeCode(rawType) === null) {
      error(`Unknown record type “${rawType}”.`, line);
      return null;
    }
    index += 1;
    const rdataTokens = restTokens.slice(index);
    const parsed = canonicalRdata(type, rdataTokens, origin);
    for (const message of parsed.errors) error(`${type}: ${message}`, line);
    for (const message of parsed.warnings) warn(`${type}: ${message}`, line);

    if (ttl === null) {
      ttl = defaultTTL ?? lastTTL ?? null;
    } else {
      lastTTL = ttl;
    }

    const record = {
      owner,
      name: owner,
      type,
      class: recordClass,
      ttl,
      ttlExplicit,
      classExplicit,
      data: parsed.data,
      rdata: parsed.rdata,
      tokens: rdataTokens.map(tokenValue),
      raw: [ownerValue, ...restTokens.map(tokenValue)].join(' '),
      origin,
      file: currentFile,
      line,
      generated: Boolean(extra.generated),
      inZone: isSubdomain(owner, initialOrigin),
    };
    records.push(record);
    lastOwner = owner;
    return record;
  }

  function substituteGenerate(template, value) {
    return String(template)
      .replace(/\$\{([^}]+)\}/g, (_, spec) => {
        const [offsetRaw = '0', widthRaw = '0', baseRaw = 'd'] = spec.split(',');
        const offset = Number.parseInt(offsetRaw, 10) || 0;
        const width = Math.max(0, Number.parseInt(widthRaw, 10) || 0);
        const number = value + offset;
        let formatter = (input) => String(input);
        if (baseRaw === 'o') formatter = (input) => input.toString(8);
        else if (baseRaw === 'x') formatter = (input) => input.toString(16);
        else if (baseRaw === 'X') formatter = (input) => input.toString(16).toUpperCase();
        else if (baseRaw === 'n') formatter = (input) => input.toString(16).slice(-1);
        else if (baseRaw === 'N') formatter = (input) => input.toString(16).toUpperCase().slice(-1);
        return formatter(number).padStart(width, '0');
      })
      .replace(/\$/g, String(value));
  }

  function handleGenerate(tokens, line) {
    if (tokens.length < 3) {
      error('$GENERATE needs a range, an owner template, a type and RDATA.', line);
      return;
    }
    const rangeText = tokenValue(tokens[0]);
    const match = rangeText.match(/^(-?\d+)-(-?\d+)(?:\/(\d+))?$/);
    if (!match) {
      error('$GENERATE range must look like “start-stop[/step]”.', line);
      return;
    }
    const start = Number(match[1]);
    const stop = Number(match[2]);
    const step = Math.abs(Number(match[3] || 1));
    if (step === 0) {
      error('$GENERATE step cannot be zero.', line);
      return;
    }
    const count = Math.floor((stop - start) / step) + 1;
    if (count < 0) {
      error('$GENERATE range ends before it starts.', line);
      return;
    }
    if (count > MAX_GENERATE) {
      error(`$GENERATE would create ${count} records; the safety limit is ${MAX_GENERATE}.`, line);
      return;
    }
    const ownerTemplate = tokenValue(tokens[1]);
    const rest = tokens.slice(2);
    directives.push({ directive: '$GENERATE', value: rangeText, line, file: currentFile, count });
    for (let value = start; value <= stop; value += step) {
      const owner = substituteGenerate(ownerTemplate, value);
      const generatedRest = rest.map((token) => {
        if (token && typeof token === 'object') {
          return { ...token, value: substituteGenerate(token.value, value) };
        }
        return { value: substituteGenerate(token, value), quoted: false };
      });
      parseRecord(owner, generatedRest, line, { generated: true });
      generatedCount += 1;
    }
  }

  function parseDirective(tokens, line, stack) {
    const directive = tokenValue(tokens[0]).toUpperCase();
    const args = tokens.slice(1);
    if (directive === '$ORIGIN') {
      if (args.length !== 1) {
        error('$ORIGIN expects exactly one domain name.', line);
        return;
      }
      const value = tokenValue(args[0]);
      const next = normalizeName(value, origin);
      const validation = validateDomainName(next, { allowWildcard: false, allowUnderscore: true });
      if (!validation.valid) {
        for (const message of validation.errors) error(`$ORIGIN: ${message}`, line);
      }
      origin = next;
      directives.push({ directive, value: next, line, file: currentFile });
      return;
    }
    if (directive === '$TTL') {
      if (args.length !== 1) {
        error('$TTL expects exactly one TTL value.', line);
        return;
      }
      const value = parseTTL(tokenValue(args[0]));
      if (value === null) error(`Invalid $TTL value “${tokenValue(args[0])}”.`, line);
      else {
        defaultTTL = value;
        lastTTL = value;
        directives.push({ directive, value, line, file: currentFile });
      }
      return;
    }
    if (directive === '$INCLUDE') {
      if (args.length < 1 || args.length > 2) {
        error('$INCLUDE expects a file name and an optional origin.', line);
        return;
      }
      const requested = tokenValue(args[0]);
      const includeOrigin = args[1] ? normalizeName(tokenValue(args[1]), origin) : origin;
      const resolved = options.resolveInclude?.(requested, currentFile) || null;
      directives.push({ directive, value: requested, origin: includeOrigin, line, file: currentFile, resolved: Boolean(resolved) });
      if (!resolved) {
        error(`$INCLUDE file “${requested}” was not found in this workspace.`, line);
        return;
      }
      if (stack.includes(resolved.path)) {
        error(`$INCLUDE cycle detected: “${requested}” is already being parsed.`, line);
        return;
      }
      includedFiles.add(resolved.path);
      const savedOrigin = origin;
      const savedOwner = lastOwner;
      const savedTTL = lastTTL;
      parseContent(resolved.content, resolved.path, includeOrigin, [...stack, resolved.path]);
      origin = savedOrigin;
      lastOwner = savedOwner;
      lastTTL = savedTTL;
      return;
    }
    if (directive === '$GENERATE') {
      handleGenerate(args, line);
      return;
    }
    error(`Unknown master-file directive “${tokenValue(tokens[0])}”.`, line);
  }

  function readLogicalLine(lineArray, start) {
    let index = start;
    let buffer = '';
    let depth = 0;
    let inQuote = false;
    let startedWithWhitespace = false;
    let sawContent = false;
    const startLine = start + 1;

    while (index < lineArray.length) {
      const line = lineArray[index];
      if (!sawContent) {
        const trimmed = line.trimStart();
        if (!trimmed || trimmed.startsWith(';')) {
          index += 1;
          continue;
        }
        startedWithWhitespace = /^[ \t]/.test(line);
        sawContent = true;
      }
      let position = 0;
      while (position < line.length) {
        const char = line[position];
        if (inQuote) {
          if (char === '\\' && position + 1 < line.length) {
            buffer += char + line[position + 1];
            position += 2;
            continue;
          }
          buffer += char;
          if (char === '"') inQuote = false;
          position += 1;
          continue;
        }
        if (char === '"') {
          inQuote = true;
          buffer += char;
          position += 1;
          continue;
        }
        if (char === '\\' && position + 1 < line.length) {
          buffer += char + line[position + 1];
          position += 2;
          continue;
        }
        if (char === ';') break;
        if (char === '(') {
          depth += 1;
          buffer += ' ';
          position += 1;
          continue;
        }
        if (char === ')') {
          depth -= 1;
          if (depth < 0) {
            error('Unmatched closing parenthesis.', startLine + index - start);
            depth = 0;
          }
          buffer += ' ';
          position += 1;
          continue;
        }
        buffer += char;
        position += 1;
      }
      index += 1;
      if (depth === 0 && !inQuote) break;
      buffer += ' ';
    }

    if (inQuote) error('Unclosed quoted string.', startLine);
    if (depth > 0) error('Unclosed parenthesis.', startLine);
    return { text: buffer.trim(), startLine, next: index, startedWithWhitespace };
  }

  function parseContent(content, contentFile, contentOrigin, stack) {
    const previousFile = currentFile;
    const previousOrigin = origin;
    currentFile = contentFile;
    origin = contentOrigin;
    const lineArray = normalizeNewlines(content).replace(/^\uFEFF/, '').split('\n');
    let lineIndex = 0;
    while (lineIndex < lineArray.length) {
      const result = readLogicalLine(lineArray, lineIndex);
      lineIndex = result.next;
      if (!result.text) continue;
      const tokens = tokenizeFields(result.text);
      if (tokens.length === 0) continue;
      const first = tokenValue(tokens[0]);
      if (first.startsWith('$')) {
        parseDirective(tokens, result.startLine, stack);
        continue;
      }
      let ownerValue;
      let restTokens;
      if (result.startedWithWhitespace) {
        if (!lastOwner) {
          error('Record omits its owner but no previous owner exists.', result.startLine);
          continue;
        }
        ownerValue = lastOwner;
        restTokens = tokens;
      } else {
        ownerValue = first;
        restTokens = tokens.slice(1);
      }
      parseRecord(ownerValue, restTokens, result.startLine);
    }
    currentFile = previousFile;
    origin = previousOrigin;
  }

  parseContent(text, entryFile, initialOrigin, [entryFile]);

  const soaRecords = records.filter((record) => record.type === 'SOA' && record.owner === initialOrigin);
  const apexNS = records.filter((record) => record.type === 'NS' && record.owner === initialOrigin);
  const ttlValues = records.map((record) => record.ttl).filter((ttl) => ttl !== null && ttl !== undefined);

  return {
    origin: initialOrigin,
    file: entryFile,
    records,
    directives,
    errors,
    warnings,
    includedFiles: Array.from(includedFiles),
    defaultTTL,
    generatedCount,
    soa: soaRecords[0] || null,
    apexNS,
    ttlSet: Array.from(new Set(ttlValues)).sort((a, b) => a - b),
    stats: {
      records: records.length,
      names: new Set(records.map((record) => record.owner)).size,
      types: new Set(records.map((record) => record.type)).size,
      errors: errors.length,
      warnings: warnings.length,
      generated: generatedCount,
    },
  };
}
