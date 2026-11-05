/* Builds a multi-file BIND model from a browser workspace. */

import { normalizeNewlines, sanitizeArchivePath, simpleHash, uid } from '../utils.js';
import {
  ensureTrailingDot,
  isReverseName,
  normalizeName,
  stripTrailingDot,
} from './names.js';
import { findStatements, flattenStatements, parseNamed, statementToText, walkStatements } from './named-parser.js';
import { parseZone } from './zone-parser.js';

const NAMED_EXTENSIONS = new Set(['.conf', '.named', '.options', '.local', '.cfg']);
const ZONE_EXTENSIONS = new Set(['.zone', '.db', '.rev', '.hosts', '.signed', '.nzf']);
const NAMED_HINT = /(^|\s)(options|include|zone|view|acl|logging|controls|key|trust-anchors|managed-keys|trusted-keys|response-policy|server|statistics-channels|primaries|masters|dnssec-policy)\b/m;
const ZONE_HINT = /(^|\s)(\$ORIGIN|\$TTL|\$INCLUDE|\$GENERATE|SOA|NS|A|AAAA|CNAME|MX|TXT|SRV|CAA|DS|DNSKEY|RRSIG|NSEC3?|PTR)\b/m;

export function normalizeWorkspacePath(path, fallback = 'file') {
  const clean = sanitizeArchivePath(path);
  return clean || fallback;
}

export function detectFileKind(path, content = '') {
  const lower = String(path || '').toLowerCase();
  const name = lower.split('/').pop() || lower;
  const extension = name.includes('.') ? `.${name.split('.').pop()}` : '';
  if (name === 'named.conf' || name.startsWith('named.conf.') || name.endsWith('.named.conf')) return 'named';
  if (/(^|\/)named\.conf(\.|$)/.test(lower)) return 'named';
  if (ZONE_EXTENSIONS.has(extension)) return 'zone';
  if (NAMED_EXTENSIONS.has(extension)) {
    if (ZONE_HINT.test(content) && /\bSOA\b/.test(content) && !/\bzone\s+["']/.test(content)) return 'zone';
    return 'named';
  }
  if (name.endsWith('.key') || name.endsWith('.private') || name.endsWith('.jnl')) return 'other';
  if (name.endsWith('.json') || name.endsWith('.yaml') || name.endsWith('.yml')) return 'other';
  if (/\bSOA\b/.test(content) && /\b(NS|A|AAAA|MX|TXT|CNAME)\b/.test(content)) return 'zone';
  if (NAMED_HINT.test(content) && /[{};]/.test(content)) return 'named';
  if (ZONE_HINT.test(content)) return 'zone';
  return 'other';
}

export function makeWorkspaceFile(path, content, options = {}) {
  const normalizedPath = normalizeWorkspacePath(path, 'unnamed.conf');
  const text = normalizeNewlines(String(content ?? ''));
  return {
    id: options.id || uid('file'),
    path: normalizedPath,
    name: normalizedPath.split('/').pop() || normalizedPath,
    content: text,
    originalContent: options.originalContent ?? text,
    kind: options.kind || detectFileKind(normalizedPath, text),
    addedAt: options.addedAt || new Date().toISOString(),
    updatedAt: options.updatedAt || new Date().toISOString(),
    size: new TextEncoder().encode(text).length,
  };
}

export function createWorkspace(name, files, options = {}) {
  const now = new Date().toISOString();
  const normalizedFiles = files.map((file) => {
    if (file.id && file.path && typeof file.content === 'string') {
      return {
        ...file,
        path: normalizeWorkspacePath(file.path, 'unnamed.conf'),
        content: normalizeNewlines(file.content),
        originalContent: normalizeNewlines(file.originalContent ?? file.content),
        kind: file.kind || detectFileKind(file.path, file.content),
      };
    }
    return makeWorkspaceFile(file.path, file.content, file);
  });
  const entry = options.entry || guessEntryFile(normalizedFiles);
  return {
    id: options.id || uid('workspace'),
    name: name || 'Imported BIND workspace',
    entry,
    files: normalizedFiles,
    createdAt: options.createdAt || now,
    updatedAt: options.updatedAt || now,
    source: options.source || 'import',
    notes: options.notes || '',
  };
}

export function guessEntryFile(files) {
  const named = files.filter((file) => detectFileKind(file.path, file.content) === 'named');
  if (named.length === 0) return files[0]?.path || null;
  const root = named.find((file) => /(^|\/)named\.conf$/.test(file.path));
  if (root) return root.path;
  const scored = named.map((file) => ({
    path: file.path,
    score: (file.content.match(/\bzone\s+["']/g) || []).length * 5 + (file.content.match(/\binclude\s+["']/g) || []).length,
  })).sort((left, right) => right.score - left.score);
  return scored[0]?.path || named[0].path;
}

export function fileKindLabel(kind) {
  return {
    named: 'named.conf',
    zone: 'zone file',
    other: 'other',
  }[kind] || 'file';
}

export function workspaceFingerprint(workspace) {
  const content = (workspace?.files || [])
    .map((file) => `${file.path}\n${file.content}`)
    .sort()
    .join('\n---\n');
  return simpleHash(content);
}

function buildFileIndex(files) {
  const exact = new Map();
  const lower = new Map();
  const basename = new Map();
  for (const file of files) {
    exact.set(file.path, file);
    lower.set(file.path.toLowerCase(), file);
    const name = file.path.split('/').pop().toLowerCase();
    if (!basename.has(name)) basename.set(name, []);
    basename.get(name).push(file);
  }
  return { exact, lower, basename };
}

function resolveFile(requestedPath, fromPath, directory, index) {
  const requested = String(requestedPath ?? '').replace(/\\/g, '/').replace(/^\.\//, '');
  if (!requested) return null;
  const candidates = [];
  const fromDir = fromPath ? fromPath.split('/').slice(0, -1).join('/') : '';
  if (fromDir) candidates.push(`${fromDir}/${requested}`);
  if (directory) {
    const dir = String(directory).replace(/\\/g, '/').replace(/^\/+/, '').replace(/\/+$/, '');
    if (dir) candidates.push(`${dir}/${requested}`);
  }
  candidates.push(requested);
  if (requested.startsWith('/')) {
    const withoutRoot = requested.replace(/^\/+/, '');
    candidates.push(withoutRoot);
    const parts = withoutRoot.split('/');
    for (let indexPart = 1; indexPart < parts.length; indexPart += 1) {
      candidates.push(parts.slice(indexPart).join('/'));
    }
  }
  const normalized = Array.from(new Set(candidates.map((candidate) => sanitizeArchivePath(candidate)).filter(Boolean)));
  for (const candidate of normalized) {
    const file = index.exact.get(candidate) || index.lower.get(candidate.toLowerCase());
    if (file) return file;
  }
  for (const candidate of normalized) {
    const lowerCandidate = candidate.toLowerCase();
    const suffixMatches = Array.from(index.lower.values()).filter((file) => file.path.toLowerCase().endsWith(`/${lowerCandidate}`) || file.path.toLowerCase() === lowerCandidate);
    if (suffixMatches.length === 1) return suffixMatches[0];
    if (suffixMatches.length > 1) {
      const shortest = suffixMatches.slice().sort((left, right) => left.path.length - right.path.length)[0];
      return shortest;
    }
  }
  const base = requested.split('/').pop().toLowerCase();
  const baseMatches = index.basename.get(base) || [];
  return baseMatches.length === 1 ? baseMatches[0] : null;
}

export function inferZoneOrigin(path, content) {
  const normalized = normalizeNewlines(content);
  const originDirective = normalized.match(/^\s*\$ORIGIN\s+([^\s;]+)/im);
  if (originDirective) return ensureTrailingDot(originDirective[1].toLowerCase());
  const soaLine = normalized.match(/^\s*([^\s;()]+)\s+(?:\d+\s+)?(?:(?:IN|CH|HS)\s+)?SOA\b/im);
  if (soaLine) {
    const owner = soaLine[1];
    if (owner !== '@' && owner !== '.' && owner.includes('.')) return ensureTrailingDot(owner.toLowerCase());
  }
  let name = String(path || '').split('/').pop().toLowerCase();
  name = name.replace(/\.(zone|db|rev|hosts|signed|nzf)$/i, '').replace(/^(db|zone)\./i, '');
  if (/^\d+\.\d+\.\d+\.rev$/.test(name)) {
    const octets = name.replace(/\.rev$/, '').split('.').reverse();
    return ensureTrailingDot(`${octets.join('.')}.in-addr.arpa`);
  }
  if (/^[0-9a-f:]+\.ip6\.arpa$/.test(name)) return ensureTrailingDot(name);
  if (name && name.includes('.')) return ensureTrailingDot(name);
  return '.';
}

function bodyEntries(statement) {
  const map = new Map();
  for (const child of statement?.body || []) {
    const key = child.keyword.toLowerCase();
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(child);
  }
  return map;
}

function leafValues(statement) {
  const values = [];
  const visit = (item) => {
    if (item.type === 'word' || item.type === 'string') {
      values.push(item.value);
      return;
    }
    if (item.keyword) {
      if (!item.hasBlock && item.keyword) values.push(item.keyword);
      for (const arg of item.args || []) values.push(arg);
      for (const child of item.body || []) visit(child);
    }
  };
  for (const child of statement?.body || []) {
    if (child.keyword) values.push(child.keyword, ...(child.args || []));
    for (const grandchild of child.body || []) {
      if (grandchild.keyword) values.push(grandchild.keyword, ...(grandchild.args || []));
      for (const leaf of grandchild.body || []) visit(leaf);
    }
  }
  return values;
}

function flattenAclValues(statement) {
  const values = [];
  const walk = (items) => {
    for (const item of items || []) {
      if (item.keyword) values.push(item.keyword, ...(item.args || []));
      if (item.body?.length) walk(item.body);
    }
  };
  walk(statement?.body);
  return values;
}

function aclHas(values, needle) {
  return values.some((value) => String(value).toLowerCase() === String(needle).toLowerCase());
}

function aclIsAny(statement) {
  return aclHas(flattenAclValues(statement), 'any');
}

function aclIsNone(statement) {
  return aclHas(flattenAclValues(statement), 'none');
}

function statementArgsText(statement) {
  return (statement?.args || []).join(' ');
}

export function parseWorkspace(workspace) {
  const started = Date.now();
  const files = (workspace?.files || []).map((file) => {
    const path = normalizeWorkspacePath(file.path, 'unnamed.conf');
    return {
      ...file,
      path,
      content: normalizeNewlines(file.content || ''),
      kind: detectFileKind(path, file.content || ''),
    };
  });
  const index = buildFileIndex(files);
  const errors = [];
  const warnings = [];
  const includes = [];
  const namedResults = new Map();
  const allNamedStatements = [];
  const entryFile = workspace?.entry && files.some((file) => file.path === workspace.entry)
    ? workspace.entry
    : guessEntryFile(files);
  const namedFiles = files.filter((file) => file.kind === 'named');
  const zoneFiles = files.filter((file) => file.kind === 'zone');
  const globalOptions = new Map();
  const zones = [];
  const keys = [];
  const acls = [];
  const views = [];
  const channels = [];
  const categories = [];
  const policies = [];
  const trustAnchors = [];
  const responsePolicies = [];
  const catalogZones = [];
  const controls = [];
  const statisticsChannels = [];
  const servers = [];
  const primaries = [];
  const parseErrors = [];
  const includedOnce = new Set();
  let directory = null;

  function addError(message, file = entryFile, line = null) {
    errors.push({ message, file, line });
  }

  function addWarning(message, file = entryFile, line = null) {
    warnings.push({ message, file, line });
  }

  function parseNamedFile(file) {
    if (!file) return null;
    if (namedResults.has(file.path)) return namedResults.get(file.path);
    const parsed = parseNamed(file.content, { file: file.path });
    namedResults.set(file.path, parsed);
    for (const error of parsed.errors) parseErrors.push(error);
    if (!directory) {
      for (const optionsStatement of parsed.statements.filter((statement) => statement.keyword === 'options')) {
        const found = (optionsStatement.body || []).find((child) => child.keyword === 'directory' && child.args[0]);
        if (found) {
          directory = found.args[0];
          break;
        }
      }
    }
    return parsed;
  }

  function expandIncludes(statements, file, ancestors, stack) {
    const output = [];
    for (const statement of statements) {
      if (statement.keyword === 'include') {
        const requested = statement.args[0];
        const resolved = resolveFile(requested, file.path, directory, index);
        includes.push({
          requested,
          from: file.path,
          line: statement.line,
          path: resolved?.path || null,
          resolved: Boolean(resolved),
        });
        if (!resolved) {
          addError(`Included file “${requested}” was not found in this workspace.`, file.path, statement.line);
          output.push(statement);
          continue;
        }
        if (stack.includes(resolved.path)) {
          addError(`Include cycle detected: “${requested}” is already being loaded.`, file.path, statement.line);
          output.push(statement);
          continue;
        }
        if (includedOnce.has(resolved.path)) {
          addWarning(`File “${resolved.path}” is included more than once.`, file.path, statement.line);
        }
        includedOnce.add(resolved.path);
        const parsed = parseNamedFile(resolved);
        if (!parsed) continue;
        // Replace the include statement with the included statements at this
        // exact point in the tree, so an include inside a view keeps the view
        // context for zones, ACLs and policy.
        output.push(...expandIncludes(parsed.statements, resolved, ancestors, [...stack, resolved.path]));
        continue;
      }
      const clone = {
        ...statement,
        body: expandIncludes(statement.body || [], file, [...ancestors, statement], stack),
      };
      output.push(clone);
    }
    return output;
  }

  function loadNamed(file) {
    if (!file) return [];
    const parsed = parseNamedFile(file);
    if (!parsed) return [];
    return expandIncludes(parsed.statements, file, [], [file.path]);
  }

  if (entryFile && namedFiles.some((file) => file.path === entryFile)) {
    allNamedStatements.push(...loadNamed(namedFiles.find((file) => file.path === entryFile)));
  } else if (namedFiles.length) {
    for (const file of namedFiles) allNamedStatements.push(...loadNamed(file));
    addWarning('No single named.conf entry point was found; all named-style files were parsed and merged.', entryFile);
  }

  // Directory is often needed for file resolution; read it from any options
  // block now that the whole include tree has been parsed.
  for (const statement of findStatements(allNamedStatements, 'options')) {
    for (const child of statement.body || []) {
      if (child.keyword === 'directory' && child.args[0]) {
        directory = child.args[0];
        break;
      }
    }
    if (directory) break;
  }

  // Extract global options and top-level feature statements.
  for (const statement of allNamedStatements) {
    if (statement.keyword === 'options' && statement.hasBlock) {
      for (const child of statement.body || []) {
        const key = child.keyword.toLowerCase();
        if (!globalOptions.has(key)) globalOptions.set(key, []);
        globalOptions.get(key).push(child);
      }
    }
  }

  function collectStatements(statements, ancestors = []) {
    for (const statement of statements) {
      const ancestorsWithSelf = [...ancestors, statement];
      if (statement.keyword === 'acl') {
        acls.push({
          name: statement.args[0] || '(unnamed)',
          values: flattenAclValues(statement),
          statement,
          file: statement.file,
          line: statement.line,
        });
      } else if (statement.keyword === 'view') {
        const entries = bodyEntries(statement);
        const view = {
          name: statement.args[0] || '(unnamed)',
          statement,
          file: statement.file,
          line: statement.line,
          matchClients: entries.get('match-clients')?.[0] || null,
          matchDestinations: entries.get('match-destinations')?.[0] || null,
          recursion: entries.get('recursion')?.[0] || null,
          allowQuery: entries.get('allow-query')?.[0] || null,
          allowRecursion: entries.get('allow-recursion')?.[0] || null,
          zones: [],
        };
        views.push(view);
      } else if (statement.keyword === 'zone') {
        const className = statement.args[1] && ['IN', 'CH', 'HS'].includes(statement.args[1].toUpperCase())
          ? statement.args[1].toUpperCase()
          : 'IN';
        const entries = bodyEntries(statement);
        const viewAncestor = ancestors.slice().reverse().find((ancestor) => ancestor.keyword === 'view');
        const zoneName = normalizeName(statement.args[0] || '');
        const zone = {
          name: zoneName,
          class: className,
          view: viewAncestor?.args?.[0] || null,
          statement,
          file: statement.file,
          line: statement.line,
          type: entries.get('type')?.[0]?.args?.[0]?.toLowerCase() || null,
          fileOption: entries.get('file')?.[0]?.args?.[0] || null,
          filePath: null,
          zoneFile: null,
          parsed: null,
          options: entries,
          synthetic: false,
        };
        zones.push(zone);
        const view = views.find((candidate) => candidate.statement === viewAncestor);
        if (view) view.zones.push(zone);
      } else if (statement.keyword === 'key' && statement.hasBlock) {
        const entries = bodyEntries(statement);
        keys.push({
          name: statement.args[0] || '(unnamed)',
          algorithm: entries.get('algorithm')?.[0]?.args?.[0] || null,
          secret: entries.get('secret')?.[0]?.args?.[0] || null,
          statement,
          file: statement.file,
          line: statement.line,
        });
      } else if (statement.keyword === 'logging') {
        for (const child of statement.body || []) {
          if (child.keyword === 'channel') {
            const channelOptions = bodyEntries(child);
            channels.push({
              name: child.args[0] || '(unnamed)',
              options: channelOptions,
              statement: child,
              file: child.file,
              line: child.line,
            });
          } else if (child.keyword === 'category') {
            categories.push({
              name: child.args[0] || '(unnamed)',
              channels: (child.body || []).map((entry) => entry.keyword),
              statement: child,
              file: child.file,
              line: child.line,
            });
          }
        }
      } else if (statement.keyword === 'dnssec-policy') {
        policies.push({
          name: statement.args[0] || '(unnamed)',
          options: bodyEntries(statement),
          statement,
          file: statement.file,
          line: statement.line,
        });
      } else if (statement.keyword === 'trust-anchors' || statement.keyword === 'managed-keys' || statement.keyword === 'trusted-keys') {
        trustAnchors.push({
          kind: statement.keyword,
          statement,
          file: statement.file,
          line: statement.line,
        });
      } else if (statement.keyword === 'response-policy') {
        responsePolicies.push({ statement, file: statement.file, line: statement.line });
      } else if (statement.keyword === 'catalog-zones') {
        catalogZones.push({ statement, file: statement.file, line: statement.line });
      } else if (statement.keyword === 'controls') {
        controls.push({ statement, file: statement.file, line: statement.line });
      } else if (statement.keyword === 'statistics-channels') {
        statisticsChannels.push({ statement, file: statement.file, line: statement.line });
      } else if (statement.keyword === 'server') {
        servers.push({ address: statement.args[0], statement, file: statement.file, line: statement.line });
      } else if (statement.keyword === 'primaries' || statement.keyword === 'masters') {
        primaries.push({ name: statement.args[0], statement, file: statement.file, line: statement.line });
      }
      if (statement.body?.length) collectStatements(statement.body, ancestorsWithSelf);
    }
  }

  collectStatements(allNamedStatements);

  // Parse referenced zone files.
  for (const zone of zones) {
    const zoneEntries = zone.options;
    const fileStatement = zoneEntries.get('file')?.[0];
    if (fileStatement) zone.fileOption = fileStatement.args[0] || zone.fileOption;
    if (zoneEntries.get('in-view')?.[0]) {
      zone.inView = zoneEntries.get('in-view')[0].args[0] || null;
    }
    if (!zone.fileOption) continue;
    const resolved = resolveFile(zone.fileOption, zone.file, directory, index);
    if (!resolved) {
      if (zone.type !== 'hint' && !zone.inView) {
        addError(`Zone “${stripTrailingDot(zone.name)}” references “${zone.fileOption}”, which is not in this workspace.`, zone.file, zone.line);
      } else if (zone.type === 'hint') {
        addWarning(`Zone “${stripTrailingDot(zone.name)}” uses a hints file that is not in this workspace.`, zone.file, zone.line);
      }
      continue;
    }
    zone.filePath = resolved.path;
    zone.zoneFile = resolved;
    zone.parsed = parseZone(resolved.content, {
      origin: zone.name,
      file: resolved.path,
      resolveInclude: (requested, from) => {
        const included = resolveFile(requested, from, directory, index);
        return included ? { path: included.path, content: included.content } : null;
      },
    });
  }

  // Parse zone files that were not referenced by named.conf, so a zone-only
  // workspace is still useful.
  const referenced = new Set(zones.map((zone) => zone.filePath).filter(Boolean));
  for (const file of zoneFiles) {
    if (referenced.has(file.path)) continue;
    const origin = inferZoneOrigin(file.path, file.content);
    let parsed = parseZone(file.content, {
      origin,
      file: file.path,
      resolveInclude: (requested, from) => {
        const included = resolveFile(requested, from, directory, index);
        return included ? { path: included.path, content: included.content } : null;
      },
    });
    if (parsed.soa && parsed.soa.owner && parsed.origin === '.') {
      parsed = parseZone(file.content, {
        origin: parsed.soa.owner,
        file: file.path,
        resolveInclude: (requested, from) => {
          const included = resolveFile(requested, from, directory, index);
          return included ? { path: included.path, content: included.content } : null;
        },
      });
    }
    zones.push({
      name: parsed.origin,
      class: 'IN',
      view: null,
      statement: null,
      file: file.path,
      line: 1,
      type: 'file',
      fileOption: file.path,
      filePath: file.path,
      zoneFile: file,
      parsed,
      options: new Map(),
      synthetic: true,
    });
  }

  // Re-run named parse errors into the model. Zone parse errors are counted
  // separately so the analyzer can explain them in zone context.
  const zoneErrors = zones.flatMap((zone) => (zone.parsed?.errors || []).map((error) => ({ ...error, zone: zone.name })));
  const zoneWarnings = zones.flatMap((zone) => (zone.parsed?.warnings || []).map((warning) => ({ ...warning, zone: zone.name })));

  const optionCount = Array.from(globalOptions.values()).reduce((total, list) => total + list.length, 0);
  const recordCount = zones.reduce((total, zone) => total + (zone.parsed?.records?.length || 0), 0);
  const hasNamed = allNamedStatements.length > 0;
  const summary = {
    files: files.length,
    namedFiles: namedFiles.length,
    zoneFiles: zoneFiles.length,
    statements: allNamedStatements.length,
    options: optionCount,
    zones: zones.length,
    records: recordCount,
    keys: keys.length,
    acls: acls.length,
    views: views.length,
    includes: includes.length,
    unresolvedIncludes: includes.filter((item) => !item.resolved).length,
    errors: errors.length + parseErrors.length + zoneErrors.length,
    warnings: warnings.length + zoneWarnings.length,
    parseMs: Date.now() - started,
  };

  return {
    workspace,
    files,
    entryFile,
    namedFiles,
    zoneFiles,
    entryParsed: entryFile ? namedResults.get(entryFile) || null : null,
    named: {
      statements: allNamedStatements,
      files: Array.from(namedResults.values()),
      parseErrors,
    },
    hasNamed,
    options: globalOptions,
    zones,
    keys,
    acls,
    views,
    channels,
    categories,
    policies,
    trustAnchors,
    responsePolicies,
    catalogZones,
    controls,
    statisticsChannels,
    servers,
    primaries,
    includes,
    errors,
    warnings,
    parseErrors,
    zoneErrors,
    zoneWarnings,
    directory,
    summary,
    stats: summary,
    parsedAt: new Date().toISOString(),
  };
}

/* ------------------------------------------------------------------ */
/* Convenience accessors for analyzer/UI                               */
/* ------------------------------------------------------------------ */

export function optionEntries(model, name) {
  return model?.options?.get(String(name).toLowerCase()) || [];
}

export function optionEntry(model, name) {
  return optionEntries(model, name)[0] || null;
}

export function optionValues(model, name) {
  const entry = optionEntry(model, name);
  if (!entry) return [];
  return [...(entry.args || []), ...leafValues(entry)];
}

export function optionEnabled(model, name) {
  const entry = optionEntry(model, name);
  if (!entry) return null;
  const first = entry.args?.[0] || leafValues(entry)[0];
  if (!first) return null;
  const text = String(first).toLowerCase();
  if (['yes', 'true', 'on'].includes(text)) return true;
  if (['no', 'false', 'off'].includes(text)) return false;
  return first;
}

export function zoneOption(zone, name) {
  return zone?.options?.get(String(name).toLowerCase())?.[0] || null;
}

export function zoneOptionValue(zone, name) {
  const entry = zoneOption(zone, name);
  if (!entry) return null;
  return entry.args?.[0] ?? leafValues(entry)[0] ?? null;
}

export function zoneAclValues(zone, name) {
  const entry = zoneOption(zone, name);
  return entry ? flattenAclValues(entry) : [];
}

export function globalAclValues(model, name) {
  const entry = optionEntry(model, name);
  return entry ? flattenAclValues(entry) : [];
}

export function isAnyAcl(entry) {
  return aclIsAny(entry);
}

export function isNoneAcl(entry) {
  return aclIsNone(entry);
}

export function optionText(model, name) {
  const entry = optionEntry(model, name);
  return entry ? statementToText(entry.statement).replace(/\s+/g, ' ').trim() : '';
}

export function zoneText(zone, name) {
  const entry = zoneOption(zone, name);
  return entry ? statementToText(entry.statement).replace(/\s+/g, ' ').trim() : '';
}

export function configStatementsFlat(model) {
  return flattenStatements(model?.named?.statements || []);
}

export function zoneByName(model, name) {
  const normalized = ensureTrailingDot(String(name || '').toLowerCase());
  return model?.zones?.find((zone) => zone.name === normalized) || null;
}

export function zoneDisplayName(zone) {
  return stripTrailingDot(zone?.name || '') || '.';
}

export function isReverseZone(zone) {
  return isReverseName(zone?.name || '');
}

export function workspaceFilesById(workspace) {
  return new Map((workspace?.files || []).map((file) => [file.id, file]));
}

export function fileByPath(workspace, path) {
  const normalized = normalizeWorkspacePath(path);
  return (workspace?.files || []).find((file) => file.path === normalized)
    || (workspace?.files || []).find((file) => file.path.toLowerCase() === normalized.toLowerCase())
    || null;
}

export function namedStatementMatches(statement, keyword) {
  return String(statement?.keyword || '').toLowerCase() === String(keyword || '').toLowerCase();
}

export function gatherZoneRecords(model) {
  return (model?.zones || []).flatMap((zone) => (zone.parsed?.records || []).map((record) => ({ ...record, zone })));
}

export { walkStatements, findStatements, statementToText, bodyEntries, flattenAclValues };
