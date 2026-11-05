/* Zone-file value parsing and canonicalisation. */

import {
  canonicalIp,
  canonicalIPv4,
  canonicalIPv6,
  normalizeName,
  stripTrailingDot,
} from './names.js';
import { normalizeType, typeCode } from './types.js';
import { base64ToBytes, bytesToHex } from '../utils.js';

export function tokenValue(token) {
  if (token && typeof token === 'object') return token.value ?? '';
  return String(token ?? '');
}

export function tokenQuoted(token) {
  return Boolean(token && typeof token === 'object' && token.quoted);
}

export function parseTTL(value) {
  const text = String(value ?? '').trim().toLowerCase();
  if (!text) return null;
  if (/^\d+$/.test(text)) {
    const number = Number(text);
    return Number.isSafeInteger(number) && number >= 0 && number <= 0x7fffffff ? number : null;
  }
  const units = { w: 604800, d: 86400, h: 3600, m: 60, s: 1 };
  let total = 0;
  let index = 0;
  const pattern = /(\d+)([wdhms])/g;
  let match;
  while ((match = pattern.exec(text)) !== null) {
    if (match.index !== index) return null;
    total += Number(match[1]) * units[match[2]];
    index = pattern.lastIndex;
  }
  if (index !== text.length) return null;
  return total <= 0x7fffffff ? total : null;
}

export function formatTTL(seconds) {
  const value = Number(seconds);
  if (!Number.isFinite(value) || value < 0) return 'unknown';
  if (value === 0) return '0';
  const units = [
    [604800, 'w'],
    [86400, 'd'],
    [3600, 'h'],
    [60, 'm'],
    [1, 's'],
  ];
  let remaining = value;
  let output = '';
  for (const [size, suffix] of units) {
    if (remaining >= size) {
      const count = Math.floor(remaining / size);
      output += `${count}${suffix}`;
      remaining -= count * size;
    }
  }
  return output || '0';
}

export function formatTtlVerbose(seconds) {
  if (seconds === null || seconds === undefined) return 'not set';
  return `${formatTTL(seconds)} (${Number(seconds).toLocaleString()} seconds)`;
}

export function quoteDnsString(value) {
  return `"${String(value ?? '')
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/[\u0000-\u001f\u007f]/g, (char) => `\\${String(char.charCodeAt(0)).padStart(3, '0')}`)}"`;
}

export function unescapeDnsString(value) {
  return String(value ?? '')
    .replace(/\\(\d{3})/g, (_, digits) => String.fromCharCode(Number(digits) % 256))
    .replace(/\\x([0-9a-f]{2})/gi, (_, hex) => String.fromCharCode(Number.parseInt(hex, 16)))
    .replace(/\\(.)/g, '$1');
}

export function tokenizeFields(text) {
  const tokens = [];
  let index = 0;
  const input = String(text ?? '');
  while (index < input.length) {
    while (index < input.length && /\s/.test(input[index])) index += 1;
    if (index >= input.length) break;
    if (input[index] === '"') {
      index += 1;
      let value = '';
      while (index < input.length) {
        const char = input[index];
        if (char === '\\' && index + 1 < input.length) {
          const next = input[index + 1];
          if (/\d/.test(next)) {
            const digits = input.slice(index + 1, index + 4);
            if (/^\d{3}$/.test(digits)) {
              value += String.fromCharCode(Number(digits) % 256);
              index += 4;
              continue;
            }
          }
          if (next === 'x' && /^[0-9a-f]{2}$/i.test(input.slice(index + 2, index + 4))) {
            value += String.fromCharCode(Number.parseInt(input.slice(index + 2, index + 4), 16));
            index += 4;
            continue;
          }
          value += next;
          index += 2;
          continue;
        }
        if (char === '"') {
          index += 1;
          break;
        }
        value += char;
        index += 1;
      }
      tokens.push({ value, quoted: true });
      continue;
    }
    let value = '';
    while (index < input.length && !/\s/.test(input[index])) {
      if (input[index] === '\\' && index + 1 < input.length) {
        value += input[index];
        value += input[index + 1];
        index += 2;
      } else {
        value += input[index];
        index += 1;
      }
    }
    tokens.push({ value, quoted: false });
  }
  return tokens;
}

function nameFrom(token, origin) {
  return normalizeName(tokenValue(token), origin);
}

function numeric(value, min, max) {
  if (!/^\d+$/.test(String(value ?? '').trim())) return null;
  const number = Number(value);
  return Number.isSafeInteger(number) && number >= min && number <= max ? number : null;
}

function numberToken(token, min, max) {
  return numeric(tokenValue(token), min, max);
}

function canonicalTypes(tokens) {
  return tokens
    .map((token) => normalizeType(tokenValue(token)))
    .filter(Boolean)
    .sort();
}

export function parseDnssecTime(value) {
  const text = String(value ?? '').trim();
  if (!text) return null;
  if (/^\d{14}$/.test(text)) {
    const year = Number(text.slice(0, 4));
    const month = Number(text.slice(4, 6));
    const day = Number(text.slice(6, 8));
    const hour = Number(text.slice(8, 10));
    const minute = Number(text.slice(10, 12));
    const second = Number(text.slice(12, 14));
    const date = Date.UTC(year, month - 1, day, hour, minute, second);
    return Number.isNaN(date) ? null : Math.floor(date / 1000);
  }
  if (/^\d{1,10}$/.test(text)) return Number(text);
  return null;
}

export function formatDnssecTime(value) {
  const seconds = parseDnssecTime(value);
  if (seconds === null) return String(value ?? '');
  return new Date(seconds * 1000).toISOString().replace('.000Z', 'Z');
}

/**
 * Parse and canonicalise RDATA. Returns display/canonical text plus a structured
 * `data` value that comparison code can use without re-parsing.
 */
export function canonicalRdata(type, tokens, origin = '.') {
  const recordType = normalizeType(type);
  const values = tokens.map(tokenValue);
  const warnings = [];
  const errors = [];
  const requireCount = (count, label = 'fields') => {
    if (values.length !== count) {
      errors.push(`${recordType} expects ${count} ${label}; found ${values.length}.`);
      return false;
    }
    return true;
  };

  switch (recordType) {
    case 'A': {
      if (!requireCount(1, 'address')) break;
      const address = canonicalIPv4(values[0]);
      if (!address) errors.push(`“${values[0]}” is not a valid IPv4 address.`);
      return { data: { address }, rdata: address || values.join(' '), warnings, errors };
    }
    case 'AAAA': {
      if (!requireCount(1, 'address')) break;
      const address = canonicalIPv6(values[0]);
      if (!address) errors.push(`“${values[0]}” is not a valid IPv6 address.`);
      return { data: { address }, rdata: address || values.join(' '), warnings, errors };
    }
    case 'NS':
    case 'CNAME':
    case 'DNAME':
    case 'PTR':
    case 'MB':
    case 'MG':
    case 'MR': {
      if (!requireCount(1, 'target name')) break;
      const target = nameFrom(tokens[0], origin);
      return { data: { target }, rdata: target, warnings, errors };
    }
    case 'MX': {
      if (!requireCount(2, 'fields (preference exchange)')) break;
      const preference = numberToken(tokens[0], 0, 65535);
      if (preference === null) errors.push('MX preference must be an integer from 0 to 65535.');
      const exchange = nameFrom(tokens[1], origin);
      return { data: { preference, exchange }, rdata: `${preference ?? values[0]} ${exchange}`, warnings, errors };
    }
    case 'SOA': {
      if (!requireCount(7, 'fields (MNAME RNAME SERIAL REFRESH RETRY EXPIRE MINIMUM)')) break;
      const mname = nameFrom(tokens[0], origin);
      const rname = nameFrom(tokens[1], origin);
      const serial = numeric(values[2], 0, 0xffffffff);
      const refresh = parseTTL(values[3]);
      const retry = parseTTL(values[4]);
      const expire = parseTTL(values[5]);
      const minimum = parseTTL(values[6]);
      if (serial === null) errors.push('SOA serial must be an unsigned 32-bit integer.');
      if (refresh === null) errors.push('SOA refresh is not a valid TTL.');
      if (retry === null) errors.push('SOA retry is not a valid TTL.');
      if (expire === null) errors.push('SOA expire is not a valid TTL.');
      if (minimum === null) errors.push('SOA minimum is not a valid TTL.');
      return {
        data: { mname, rname, serial, refresh, retry, expire, minimum },
        rdata: `${mname} ${rname} ${serial ?? values[2]} ${refresh ?? values[3]} ${retry ?? values[4]} ${expire ?? values[5]} ${minimum ?? values[6]}`,
        warnings,
        errors,
      };
    }
    case 'TXT':
    case 'SPF': {
      if (values.length === 0) errors.push(`${recordType} needs at least one character-string.`);
      const strings = tokens.map((token) => tokenValue(token));
      for (const string of strings) {
        if (new TextEncoder().encode(string).length > 255) errors.push('Each TXT character-string is limited to 255 octets; split long values into multiple strings.');
      }
      return {
        data: { strings },
        rdata: strings.map((string) => quoteDnsString(string)).join(' '),
        warnings,
        errors,
      };
    }
    case 'SRV': {
      if (!requireCount(4, 'fields (priority weight port target)')) break;
      const priority = numberToken(tokens[0], 0, 65535);
      const weight = numberToken(tokens[1], 0, 65535);
      const port = numberToken(tokens[2], 0, 65535);
      for (const [label, value] of [['priority', priority], ['weight', weight], ['port', port]]) {
        if (value === null) errors.push(`SRV ${label} must be an integer from 0 to 65535.`);
      }
      const target = nameFrom(tokens[3], origin);
      return {
        data: { priority, weight, port, target },
        rdata: `${priority ?? values[0]} ${weight ?? values[1]} ${port ?? values[2]} ${target}`,
        warnings,
        errors,
      };
    }
    case 'CAA': {
      if (!requireCount(3, 'fields (flags tag value)')) break;
      const flags = numberToken(tokens[0], 0, 255);
      const tag = values[1].toLowerCase();
      if (flags === null) errors.push('CAA flags must be an integer from 0 to 255.');
      if (!/^[a-z0-9-]+$/i.test(tag)) errors.push('CAA tag must contain only letters, digits and hyphens.');
      const value = values[2];
      return {
        data: { flags, tag, value },
        rdata: `${flags ?? values[0]} ${tag} ${quoteDnsString(value)}`,
        warnings,
        errors,
      };
    }
    case 'DS':
    case 'CDS': {
      if (!requireCount(4, 'fields (keytag algorithm digest-type digest)')) break;
      const keyTag = numberToken(tokens[0], 0, 65535);
      const algorithm = numberToken(tokens[1], 0, 255);
      const digestType = numberToken(tokens[2], 0, 255);
      const digest = values[3].replace(/\s+/g, '').toUpperCase();
      if (keyTag === null) errors.push(`${recordType} key tag must be 0–65535.`);
      if (algorithm === null) errors.push(`${recordType} algorithm must be 0–255.`);
      if (digestType === null) errors.push(`${recordType} digest type must be 0–255.`);
      if (!/^[0-9A-F]+$/.test(digest) || digest.length % 2 !== 0) errors.push(`${recordType} digest must be hexadecimal.`);
      return {
        data: { keyTag, algorithm, digestType, digest },
        rdata: `${keyTag ?? values[0]} ${algorithm ?? values[1]} ${digestType ?? values[2]} ${digest}`,
        warnings,
        errors,
      };
    }
    case 'DNSKEY':
    case 'CDNSKEY': {
      if (values.length < 4) {
        errors.push(`${recordType} expects flags protocol algorithm public-key.`);
        break;
      }
      const flags = numberToken(tokens[0], 0, 65535);
      const protocol = numberToken(tokens[1], 0, 255);
      const algorithm = numberToken(tokens[2], 0, 255);
      const publicKey = values.slice(3).join('');
      if (flags === null) errors.push(`${recordType} flags must be 0–65535.`);
      if (protocol === null) errors.push(`${recordType} protocol must be 0–255.`);
      if (algorithm === null) errors.push(`${recordType} algorithm must be 0–255.`);
      if (!/^[A-Za-z0-9+/=]+$/.test(publicKey)) errors.push(`${recordType} public key must be base64.`);
      return {
        data: { flags, protocol, algorithm, publicKey },
        rdata: `${flags ?? values[0]} ${protocol ?? values[1]} ${algorithm ?? values[2]} ${publicKey}`,
        warnings,
        errors,
      };
    }
    case 'RRSIG': {
      if (values.length < 9) {
        errors.push('RRSIG expects type-covered algorithm labels original-TTL expiration inception key-tag signer signature.');
        break;
      }
      const covered = normalizeType(values[0]);
      const algorithm = numberToken(tokens[1], 0, 255);
      const labels = numberToken(tokens[2], 0, 255);
      const originalTTL = parseTTL(values[3]);
      const expiration = parseDnssecTime(values[4]);
      const inception = parseDnssecTime(values[5]);
      const keyTag = numberToken(tokens[6], 0, 65535);
      const signer = nameFrom(tokens[7], origin);
      const signature = values.slice(8).join('');
      if (!typeCode(covered)) errors.push(`RRSIG type covered “${values[0]}” is unknown.`);
      if (algorithm === null) errors.push('RRSIG algorithm must be 0–255.');
      if (labels === null) errors.push('RRSIG labels must be 0–255.');
      if (originalTTL === null) errors.push('RRSIG original TTL is invalid.');
      if (expiration === null || inception === null) errors.push('RRSIG times must be YYYYMMDDHHMMSS or epoch seconds.');
      if (keyTag === null) errors.push('RRSIG key tag must be 0–65535.');
      if (!/^[A-Za-z0-9+/=]+$/.test(signature)) errors.push('RRSIG signature must be base64.');
      return {
        data: { covered, algorithm, labels, originalTTL, expiration, inception, keyTag, signer, signature },
        rdata: `${covered} ${algorithm ?? values[1]} ${labels ?? values[2]} ${originalTTL ?? values[3]} ${expiration ?? values[4]} ${inception ?? values[5]} ${keyTag ?? values[6]} ${signer} ${signature}`,
        warnings,
        errors,
      };
    }
    case 'NSEC': {
      if (values.length < 2) {
        errors.push('NSEC expects next-domain and a type bitmap.');
        break;
      }
      const next = nameFrom(tokens[0], origin);
      const types = canonicalTypes(tokens.slice(1));
      return { data: { next, types }, rdata: `${next} ${types.join(' ')}`, warnings, errors };
    }
    case 'NSEC3': {
      if (values.length < 5) {
        errors.push('NSEC3 expects hash-algorithm flags iterations salt next-hashed-owner and a type bitmap.');
        break;
      }
      const hashAlgorithm = numberToken(tokens[0], 0, 255);
      const flags = numberToken(tokens[1], 0, 255);
      const iterations = numberToken(tokens[2], 0, 65535);
      const salt = values[3].toUpperCase();
      const nextHashed = values[4].toUpperCase();
      const types = canonicalTypes(tokens.slice(5));
      if (hashAlgorithm === null) errors.push('NSEC3 hash algorithm must be 0–255.');
      if (flags === null) errors.push('NSEC3 flags must be 0–255.');
      if (iterations === null) errors.push('NSEC3 iterations must be 0–65535.');
      if (salt !== '-' && !/^[0-9A-F]+$/.test(salt)) errors.push('NSEC3 salt must be hexadecimal or “-”.');
      if (!/^[A-Z2-7]+$/.test(nextHashed)) errors.push('NSEC3 next-hashed-owner must be base32hex.');
      return {
        data: { hashAlgorithm, flags, iterations, salt, nextHashed, types },
        rdata: `${hashAlgorithm ?? values[0]} ${flags ?? values[1]} ${iterations ?? values[2]} ${salt} ${nextHashed}${types.length ? ` ${types.join(' ')}` : ''}`,
        warnings,
        errors,
      };
    }
    case 'NSEC3PARAM': {
      if (!requireCount(4, 'fields (hash-algorithm flags iterations salt)')) break;
      const hashAlgorithm = numberToken(tokens[0], 0, 255);
      const flags = numberToken(tokens[1], 0, 255);
      const iterations = numberToken(tokens[2], 0, 65535);
      const salt = values[3].toUpperCase();
      if (hashAlgorithm === null) errors.push('NSEC3PARAM hash algorithm must be 0–255.');
      if (flags === null) errors.push('NSEC3PARAM flags must be 0–255.');
      if (iterations === null) errors.push('NSEC3PARAM iterations must be 0–65535.');
      if (salt !== '-' && !/^[0-9A-F]+$/.test(salt)) errors.push('NSEC3PARAM salt must be hexadecimal or “-”.');
      return {
        data: { hashAlgorithm, flags, iterations, salt },
        rdata: `${hashAlgorithm ?? values[0]} ${flags ?? values[1]} ${iterations ?? values[2]} ${salt}`,
        warnings,
        errors,
      };
    }
    case 'TLSA':
    case 'SMIMEA': {
      if (values.length < 4) {
        errors.push(`${recordType} expects usage selector matching-type certificate-data.`);
        break;
      }
      const usage = numberToken(tokens[0], 0, 255);
      const selector = numberToken(tokens[1], 0, 255);
      const matchingType = numberToken(tokens[2], 0, 255);
      const certificate = values.slice(3).join('').toUpperCase();
      if (usage === null) errors.push(`${recordType} usage must be 0–255.`);
      if (selector === null) errors.push(`${recordType} selector must be 0–255.`);
      if (matchingType === null) errors.push(`${recordType} matching type must be 0–255.`);
      if (!/^[0-9A-F]+$/.test(certificate) || certificate.length % 2 !== 0) errors.push(`${recordType} certificate data must be hexadecimal.`);
      return {
        data: { usage, selector, matchingType, certificate },
        rdata: `${usage ?? values[0]} ${selector ?? values[1]} ${matchingType ?? values[2]} ${certificate}`,
        warnings,
        errors,
      };
    }
    case 'SSHFP': {
      if (!requireCount(3, 'fields (algorithm fingerprint-type fingerprint)')) break;
      const algorithm = numberToken(tokens[0], 0, 255);
      const fingerprintType = numberToken(tokens[1], 0, 255);
      const fingerprint = values[2].replace(/\s+/g, '').toUpperCase();
      if (algorithm === null) errors.push('SSHFP algorithm must be 0–255.');
      if (fingerprintType === null) errors.push('SSHFP fingerprint type must be 0–255.');
      if (!/^[0-9A-F]+$/.test(fingerprint)) errors.push('SSHFP fingerprint must be hexadecimal.');
      return {
        data: { algorithm, fingerprintType, fingerprint },
        rdata: `${algorithm ?? values[0]} ${fingerprintType ?? values[1]} ${fingerprint}`,
        warnings,
        errors,
      };
    }
    case 'SVCB':
    case 'HTTPS': {
      if (values.length < 2) {
        errors.push(`${recordType} expects priority target [parameters].`);
        break;
      }
      const priority = numberToken(tokens[0], 0, 65535);
      const target = nameFrom(tokens[1], origin);
      if (priority === null) errors.push(`${recordType} priority must be 0–65535.`);
      if (priority === 0 && stripTrailingDot(target) !== '') warnings.push('An AliasMode record (priority 0) cannot carry service parameters in normal use.');
      const params = values.slice(2).join(' ');
      return {
        data: { priority, target, params },
        rdata: `${priority ?? values[0]} ${target}${params ? ` ${params}` : ''}`,
        warnings,
        errors,
      };
    }
    case 'NAPTR': {
      if (!requireCount(6, 'fields (order preference flags service regexp replacement)')) break;
      const order = numberToken(tokens[0], 0, 65535);
      const preference = numberToken(tokens[1], 0, 65535);
      const replacement = nameFrom(tokens[5], origin);
      if (order === null) errors.push('NAPTR order must be 0–65535.');
      if (preference === null) errors.push('NAPTR preference must be 0–65535.');
      return {
        data: { order, preference, flags: values[2], service: values[3], regexp: values[4], replacement },
        rdata: `${order ?? values[0]} ${preference ?? values[1]} ${quoteDnsString(values[2])} ${quoteDnsString(values[3])} ${quoteDnsString(values[4])} ${replacement}`,
        warnings,
        errors,
      };
    }
    case 'URI': {
      if (!requireCount(3, 'fields (priority weight target)')) break;
      const priority = numberToken(tokens[0], 0, 65535);
      const weight = numberToken(tokens[1], 0, 65535);
      if (priority === null) errors.push('URI priority must be 0–65535.');
      if (weight === null) errors.push('URI weight must be 0–65535.');
      return {
        data: { priority, weight, target: values[2] },
        rdata: `${priority ?? values[0]} ${weight ?? values[1]} ${quoteDnsString(values[2])}`,
        warnings,
        errors,
      };
    }
    case 'HINFO': {
      if (!requireCount(2, 'fields (CPU OS)')) break;
      return {
        data: { cpu: values[0], os: values[1] },
        rdata: `${quoteDnsString(values[0])} ${quoteDnsString(values[1])}`,
        warnings,
        errors,
      };
    }
    case 'RP': {
      if (!requireCount(2, 'fields (mailbox TXT-domain)')) break;
      const mailbox = nameFrom(tokens[0], origin);
      const txt = nameFrom(tokens[1], origin);
      return { data: { mailbox, txt }, rdata: `${mailbox} ${txt}`, warnings, errors };
    }
    case 'AFSDB':
    case 'KX':
    case 'RT': {
      if (!requireCount(2, 'fields (preference target)')) break;
      const preference = numberToken(tokens[0], 0, 65535);
      const target = nameFrom(tokens[1], origin);
      if (preference === null) errors.push(`${recordType} preference must be 0–65535.`);
      return { data: { preference, target }, rdata: `${preference ?? values[0]} ${target}`, warnings, errors };
    }
    case 'CERT': {
      if (values.length < 4) {
        errors.push('CERT expects type key-tag algorithm certificate.');
        break;
      }
      const certificate = values.slice(3).join('');
      if (!/^[A-Za-z0-9+/=]+$/.test(certificate)) errors.push('CERT certificate must be base64.');
      return {
        data: { certificateType: numberToken(tokens[0], 0, 65535), keyTag: numberToken(tokens[1], 0, 65535), algorithm: numberToken(tokens[2], 0, 255), certificate },
        rdata: values.join(' '),
        warnings,
        errors,
      };
    }
    default: {
      if (values.length === 0) warnings.push(`${recordType} has no RDATA.`);
      return { data: { tokens: values }, rdata: values.join(' '), warnings, errors };
    }
  }
  return { data: { tokens: values }, rdata: values.join(' '), warnings, errors };
}

export function normalizeRdataForCompare(type, data) {
  const recordType = normalizeType(type);
  switch (recordType) {
    case 'A':
      return canonicalIPv4(data) ?? String(data).trim();
    case 'AAAA':
      return canonicalIPv6(data) ?? String(data).trim();
    case 'NS':
    case 'CNAME':
    case 'DNAME':
    case 'PTR':
      return normalizeName(data);
    case 'MX': {
      const [pref, exchange] = String(data).trim().split(/\s+/);
      return `${pref} ${normalizeName(exchange || '.')}`;
    }
    case 'SRV': {
      const parts = String(data).trim().split(/\s+/);
      if (parts.length < 4) return String(data).trim().toLowerCase();
      return `${parts[0]} ${parts[1]} ${parts[2]} ${normalizeName(parts[3])}`;
    }
    case 'TXT':
    case 'SPF': {
      const strings = [];
      for (const token of tokenizeFields(data)) strings.push(token.value);
      return JSON.stringify(strings);
    }
    case 'CAA': {
      const tokens = tokenizeFields(data);
      if (tokens.length < 3) return String(data).trim();
      return `${tokens[0].value} ${tokens[1].value.toLowerCase()} ${tokens.slice(2).map((token) => token.value).join(' ')}`;
    }
    case 'SOA': {
      const tokens = tokenizeFields(data);
      if (tokens.length < 7) return String(data).trim();
      const values = tokens.map((token) => token.value);
      return `${normalizeName(values[0])} ${normalizeName(values[1])} ${values.slice(2).join(' ')}`;
    }
    case 'DS':
    case 'CDS': {
      const parts = String(data).trim().split(/\s+/);
      return parts.map((part, index) => index === 3 ? part.toUpperCase() : part).join(' ');
    }
    case 'DNSKEY':
    case 'CDNSKEY': {
      const parts = String(data).trim().split(/\s+/);
      return `${parts.slice(0, 3).join(' ')} ${parts.slice(3).join('')}`;
    }
    case 'RRSIG': {
      const parts = String(data).trim().split(/\s+/);
      if (parts.length < 9) return String(data).trim();
      return `${normalizeType(parts[0])} ${parts.slice(1, 7).join(' ')} ${normalizeName(parts[7])} ${parts.slice(8).join('')}`;
    }
    case 'NSEC': {
      const parts = String(data).trim().split(/\s+/);
      return `${normalizeName(parts[0] || '.')} ${parts.slice(1).map((part) => normalizeType(part)).sort().join(' ')}`;
    }
    default:
      return String(data).trim().replace(/\s+/g, ' ');
  }
}

export function makeRdata(type, tokens, origin) {
  return canonicalRdata(type, tokens, origin);
}

export function dsDigestHex(data) {
  return bytesToHex(data).toUpperCase();
}

export function safeBase64Length(value) {
  try {
    return base64ToBytes(value).length;
  } catch {
    return null;
  }
}

export function displayAddress(value) {
  return canonicalIp(value) ?? String(value ?? '');
}

export function ttlSummary(ttl) {
  return ttl === null || ttl === undefined ? 'TTL not set' : `TTL ${formatTTL(ttl)}`;
}
