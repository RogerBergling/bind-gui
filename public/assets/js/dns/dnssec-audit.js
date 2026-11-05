/* Deep, browser-side DNSSEC audit over DoH. */

import {
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  concatBytes,
  hexToBytes,
  utf8,
} from '../utils.js';
import { labelsOf, nameToWire, normalizeName, parentName } from './names.js';
import { tokenizeFields } from './syntax.js';
import { algorithmInfo, digestInfo, normalizeType, typeCode } from './types.js';
import { queryDns } from './doh.js';
import {
  dnskeyTag,
  parseDnskeyRdata,
  parseDsRdata,
  parseRrsigRdata,
  walkDnssecChain,
} from './dnssec.js';

const BASE32HEX = '0123456789ABCDEFGHIJKLMNOPQRSTUV';

function u8(value) { return Uint8Array.of(value & 0xff); }
function u16(value) { return Uint8Array.of((value >> 8) & 0xff, value & 0xff); }
function u32(value) {
  return Uint8Array.of((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
}
function b64url(bytes) {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function compareBytes(left, right) {
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return left.length - right.length;
}
function stripTypePrefix(data, type) {
  return String(data ?? '').trim().replace(new RegExp(`^${type}\\s+`, 'i'), '');
}

export function base32Hex(bytes) {
  let output = '';
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      output += BASE32HEX[(buffer >> bits) & 31];
    }
  }
  if (bits > 0) output += BASE32HEX[(buffer << (5 - bits)) & 31];
  return output;
}

export function nsec3Hash(name, saltHex, iterations, algorithm = 1) {
  if (Number(algorithm) !== 1) {
    return Promise.resolve({ ok: false, error: `NSEC3 hash algorithm ${algorithm} is not supported by this audit (only SHA-1 / algorithm 1).` });
  }
  if (!globalThis.crypto?.subtle) {
    return Promise.resolve({ ok: false, error: 'Web Crypto is unavailable; serve the app over localhost or HTTPS to compute NSEC3 hashes.' });
  }
  const salt = saltHex && saltHex !== '-' ? hexToBytes(saltHex) : new Uint8Array();
  const wire = nameToWire(name);
  return (async () => {
    let digest = new Uint8Array(await crypto.subtle.digest('SHA-1', concatBytes(wire, salt)));
    for (let index = 0; index < Math.max(0, Number(iterations) || 0); index += 1) {
      digest = new Uint8Array(await crypto.subtle.digest('SHA-1', concatBytes(digest, salt)));
    }
    return { ok: true, bytes: digest, base32: base32Hex(digest), salt };
  })();
}

function typeBitmap(types) {
  const windows = new Map();
  for (const type of types) {
    const code = typeCode(type);
    if (code === null) continue;
    const window = Math.floor(code / 256);
    const bit = code % 256;
    if (!windows.has(window)) windows.set(window, new Uint8Array(Math.floor(bit / 8) + 1));
    const bytes = windows.get(window);
    if (bytes.length < Math.floor(bit / 8) + 1) {
      const next = new Uint8Array(Math.floor(bit / 8) + 1);
      next.set(bytes);
      windows.set(window, next);
    }
    windows.get(window)[Math.floor(bit / 8)] |= 0x80 >> (bit % 8);
  }
  const chunks = [];
  for (const window of Array.from(windows.keys()).sort((a, b) => a - b)) {
    const bytes = windows.get(window);
    chunks.push(u8(window), u8(bytes.length), bytes);
  }
  return concatBytes(...chunks);
}

function canonicalNameForRrsig(owner, labels) {
  const labelsArray = labelsOf(owner);
  const labelCount = Number(labels);
  if (!Number.isFinite(labelCount) || labelCount > labelsArray.length) return null;
  if (labelCount === labelsArray.length) return normalizeName(owner);
  return normalizeName(`*.${labelsArray.slice(labelsArray.length - labelCount).join('.')}`);
}

export function canonicalRdataWire(type, data) {
  const name = normalizeType(type);
  const text = stripTypePrefix(data, name);
  const tokens = tokenizeFields(text).map((token) => token.value);
  const values = tokens;
  switch (name) {
    case 'A': {
      const parts = text.split('.').map(Number);
      if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
      return Uint8Array.of(...parts);
    }
    case 'AAAA': {
      const groups = parseIPv6(text);
      if (!groups) return null;
      const bytes = new Uint8Array(16);
      groups.forEach((group, index) => {
        bytes[index * 2] = (group >> 8) & 0xff;
        bytes[index * 2 + 1] = group & 0xff;
      });
      return bytes;
    }
    case 'NS':
    case 'CNAME':
    case 'DNAME':
    case 'PTR': return nameToWire(tokens[0]);
    case 'MX': return concatBytes(u16(Number(values[0])), nameToWire(values[1]));
    case 'SOA': {
      if (values.length < 7) return null;
      return concatBytes(
        nameToWire(values[0]),
        nameToWire(values[1]),
        u32(Number(values[2])),
        u32(parseTtlWire(values[3])),
        u32(parseTtlWire(values[4])),
        u32(parseTtlWire(values[5])),
        u32(parseTtlWire(values[6])),
      );
    }
    case 'TXT': {
      const chunks = [];
      for (const token of tokenizeFields(text)) {
        const bytes = utf8(token.value);
        if (bytes.length > 255) return null;
        chunks.push(u8(bytes.length), bytes);
      }
      return concatBytes(...chunks);
    }
    case 'SRV':
      return concatBytes(u16(Number(values[0])), u16(Number(values[1])), u16(Number(values[2])), nameToWire(values[3]));
    case 'CAA': {
      const tag = utf8(values[1]);
      const value = utf8(values[2] ?? '');
      return concatBytes(u8(Number(values[0])), u8(tag.length), tag, value);
    }
    case 'DS': {
      const digest = hexToBytes(values[3]);
      return concatBytes(u16(Number(values[0])), u8(Number(values[1])), u8(Number(values[2])), digest);
    }
    case 'DNSKEY': {
      const key = parseDnskeyRdata(text);
      if (!key) return null;
      return concatBytes(u16(key.flags), u8(key.protocol), u8(key.algorithm), base64ToBytes(key.publicKey));
    }
    case 'NSEC': {
      if (values.length < 2) return null;
      return concatBytes(nameToWire(values[0]), typeBitmap(values.slice(1)));
    }
    case 'NSEC3': {
      if (values.length < 5) return null;
      const salt = values[3] === '-' ? new Uint8Array() : hexToBytes(values[3]);
      const next = values[4] === '-' ? new Uint8Array() : base32HexToBytes(values[4]);
      return concatBytes(u8(Number(values[0])), u8(Number(values[1])), u16(Number(values[2])), u8(salt.length), salt, u8(next.length), next, typeBitmap(values.slice(5)));
    }
    case 'NSEC3PARAM': {
      if (values.length < 4) return null;
      const salt = values[3] === '-' ? new Uint8Array() : hexToBytes(values[3]);
      return concatBytes(u8(Number(values[0])), u8(Number(values[1])), u16(Number(values[2])), u8(salt.length), salt);
    }
    case 'TLSA':
    case 'SMIMEA': {
      return concatBytes(u8(Number(values[0])), u8(Number(values[1])), u8(Number(values[2])), hexToBytes(values.slice(3).join('')));
    }
    case 'SSHFP':
      return concatBytes(u8(Number(values[0])), u8(Number(values[1])), hexToBytes(values[2]));
    default:
      return null;
  }
}

function parseTtlWire(value) {
  const text = String(value);
  if (/^\d+$/.test(text)) return Number(text);
  const units = { w: 604800, d: 86400, h: 3600, m: 60, s: 1 };
  let total = 0;
  for (const match of text.toLowerCase().matchAll(/(\d+)([wdhms])/g)) total += Number(match[1]) * units[match[2]];
  return total;
}


function base32HexToBytes(value) {
  const text = String(value || '').toUpperCase();
  const bytes = [];
  let buffer = 0;
  let bits = 0;
  for (const char of text) {
    const index = BASE32HEX.indexOf(char);
    if (index < 0) return new Uint8Array();
    buffer = (buffer << 5) | index;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
    }
  }
  return Uint8Array.from(bytes);
}

// Imported here rather than at the top to keep the helper module focused.
import { parseIPv6 } from './names.js';

function rrsigHeaderWire(rrsig) {
  return concatBytes(
    u16(typeCode(rrsig.covered) ?? 0),
    u8(rrsig.algorithm),
    u8(rrsig.labels),
    u32(rrsig.originalTTL),
    u32(rrsig.expiration),
    u32(rrsig.inception),
    u16(rrsig.keyTag),
    nameToWire(rrsig.signer),
  );
}

function canonicalRrset(owner, type, records, originalTTL, labels, rrsig) {
  const ownerName = canonicalNameForRrsig(owner, labels);
  if (!ownerName) return { error: 'RRSIG label count is greater than the owner name label count.' };
  const rdatas = [];
  for (const record of records) {
    const rdata = canonicalRdataWire(type, record.data);
    if (!rdata) return { error: `Cannot canonicalise ${type} RDATA for signature verification.` };
    rdatas.push(rdata);
  }
  rdatas.sort(compareBytes);
  const chunks = [rrsigHeaderWire(rrsig)];
  for (const rdata of rdatas) {
    chunks.push(nameToWire(ownerName), u16(typeCode(type)), u16(1), u32(originalTTL), u16(rdata.length), rdata);
  }
  return { data: concatBytes(...chunks), ownerName, rdataCount: rdatas.length };
}

function rsaPublicKey(key) {
  const bytes = base64ToBytes(key.publicKey);
  let offset = 0;
  let exponentLength;
  if (bytes[0] === 0) {
    if (bytes.length < 3) return null;
    exponentLength = (bytes[1] << 8) | bytes[2];
    offset = 3;
  } else {
    exponentLength = bytes[0];
    offset = 1;
  }
  const exponent = bytes.subarray(offset, offset + exponentLength);
  const modulus = bytes.subarray(offset + exponentLength);
  if (!exponent.length || !modulus.length) return null;
  return {
    kty: 'RSA',
    n: b64url(modulus),
    e: b64url(exponent),
    ext: true,
  };
}

async function importAndVerify(key, rrsig, signature, signedData) {
  const algorithm = Number(rrsig.algorithm);
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) return { status: 'unsupported', error: 'Web Crypto is unavailable.' };
  try {
    if ([1, 5, 7, 8, 10].includes(algorithm)) {
      const jwk = rsaPublicKey(key);
      if (!jwk) return { status: 'fail', error: 'Invalid RSA DNSKEY encoding.' };
      const hash = algorithm === 5 || algorithm === 7 || algorithm === 1 ? 'SHA-1' : (algorithm === 10 ? 'SHA-512' : 'SHA-256');
      const cryptoKey = await subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash }, false, ['verify']);
      const ok = await subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, cryptoKey, signature, signedData);
      return { status: ok ? 'pass' : 'fail', method: `RSASSA-PKCS1-v1_5 / ${hash}` };
    }
    if (algorithm === 13 || algorithm === 14) {
      const keyBytes = base64ToBytes(key.publicKey);
      const size = algorithm === 13 ? 32 : 48;
      if (keyBytes.length !== size * 2) return { status: 'fail', error: `ECDSA ${algorithm === 13 ? 'P-256' : 'P-384'} public key has the wrong length.` };
      const crv = algorithm === 13 ? 'P-256' : 'P-384';
      const jwk = { kty: 'EC', crv, x: b64url(keyBytes.subarray(0, size)), y: b64url(keyBytes.subarray(size)), ext: true };
      const cryptoKey = await subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: crv }, false, ['verify']);
      const hash = algorithm === 13 ? 'SHA-256' : 'SHA-384';
      const ok = await subtle.verify({ name: 'ECDSA', hash: { name: hash } }, cryptoKey, signature, signedData);
      return { status: ok ? 'pass' : 'fail', method: `ECDSA ${crv} / ${hash}` };
    }
    if (algorithm === 15) {
      if (!subtle.importKey) return { status: 'unsupported' };
      const keyBytes = base64ToBytes(key.publicKey);
      if (keyBytes.length !== 32) return { status: 'fail', error: 'Ed25519 public key must be 32 bytes.' };
      const cryptoKey = await subtle.importKey('raw', keyBytes, { name: 'Ed25519' }, false, ['verify']);
      const ok = await subtle.verify({ name: 'Ed25519' }, cryptoKey, signature, signedData);
      return { status: ok ? 'pass' : 'fail', method: 'Ed25519' };
    }
    return { status: 'unsupported', error: `RRSIG algorithm ${algorithm} is not supported by Web Crypto in this browser.` };
  } catch (error) {
    return { status: 'unsupported', error: error?.message || 'Could not import the DNSSEC public key.' };
  }
}

export async function verifyRrsetSignature({ owner, type, records, rrsig, keys }) {
  if (!rrsig || !records?.length) return { status: 'missing', error: 'No RRSIG or no RRset.' };
  const parsedRrsig = parseRrsigRdata(rrsig);
  if (!parsedRrsig) return { status: 'fail', error: 'RRSIG RDATA could not be parsed.' };
  if (parsedRrsig.covered !== normalizeType(type)) return { status: 'fail', error: `RRSIG covers ${parsedRrsig.covered}, not ${type}.` };
  let canonical;
  try {
    canonical = canonicalRrset(owner, type, records, parsedRrsig.originalTTL, parsedRrsig.labels, parsedRrsig);
  } catch (error) {
    return { status: 'fail', error: error?.message || 'Could not canonicalise the RRset.' };
  }
  if (canonical.error) return { status: 'fail', error: canonical.error };
  const candidates = (keys || []).filter((key) => key.algorithm === parsedRrsig.algorithm && key.keyTag === parsedRrsig.keyTag);
  if (!candidates.length) return { status: 'no-key', error: `No DNSKEY matches key tag ${parsedRrsig.keyTag} and algorithm ${parsedRrsig.algorithm}.`, rrsig: parsedRrsig };
  let signature;
  try {
    signature = base64ToBytes(parsedRrsig.signature);
  } catch {
    return { status: 'fail', error: 'RRSIG signature is not valid base64.' };
  }
  const attempts = [];
  for (const key of candidates) {
    try {
      const result = await importAndVerify(parseDnskeyRdata(key.data || key), parsedRrsig, signature, canonical.data);
      attempts.push(result);
      if (result.status === 'pass') return { ...result, rrsig: parsedRrsig, key, owner, type, records: canonical.rdataCount };
    } catch (error) {
      attempts.push({ status: 'unsupported', error: error?.message || 'Signature verification threw.' });
    }
  }
  return { ...attempts[0], rrsig: parsedRrsig, attempts, owner, type, records: canonical.rdataCount };
}

function canonicalNameCompare(left, right) {
  const a = labelsOf(left).reverse();
  const b = labelsOf(right).reverse();
  for (let index = 0; index < Math.min(a.length, b.length); index += 1) {
    const leftBytes = utf8(a[index]);
    const rightBytes = utf8(b[index]);
    const result = compareBytes(leftBytes, rightBytes);
    if (result !== 0) return result;
  }
  return a.length - b.length;
}

function nsecCovers(owner, next, qname) {
  const ownerVsNext = canonicalNameCompare(owner, next);
  if (canonicalNameCompare(owner, qname) === 0) return 'owner';
  if (ownerVsNext < 0) {
    return canonicalNameCompare(owner, qname) < 0 && canonicalNameCompare(qname, next) < 0 ? 'covered' : false;
  }
  return canonicalNameCompare(owner, qname) < 0 || canonicalNameCompare(qname, next) < 0 ? 'covered' : false;
}

function nsec3Covers(ownerHash, nextHash, hash) {
  const owner = String(ownerHash || '').toUpperCase();
  const next = String(nextHash || '').toUpperCase();
  const target = String(hash || '').toUpperCase();
  if (owner === target) return 'owner';
  if (!owner || !next) return false;
  if (owner < next) return owner < target && target < next ? 'covered' : false;
  return target > owner || target < next ? 'covered' : false;
}

function parseNsec3(data) {
  const values = stripTypePrefix(data, 'NSEC3').split(/\s+/).filter(Boolean);
  if (values.length < 5) return null;
  return {
    hashAlgorithm: Number(values[0]),
    flags: Number(values[1]),
    iterations: Number(values[2]),
    salt: values[3],
    nextHashed: values[4].toUpperCase(),
    types: values.slice(5).map((type) => normalizeType(type)),
    raw: values.join(' '),
  };
}

function parseNsec3Param(data) {
  const values = stripTypePrefix(data, 'NSEC3PARAM').split(/\s+/).filter(Boolean);
  if (values.length < 4) return null;
  return {
    hashAlgorithm: Number(values[0]),
    flags: Number(values[1]),
    iterations: Number(values[2]),
    salt: values[3],
    raw: values.join(' '),
  };
}

function parseNsec(data) {
  const values = stripTypePrefix(data, 'NSEC').split(/\s+/).filter(Boolean);
  if (values.length < 2) return null;
  return { next: values[0], types: values.slice(1).map((type) => normalizeType(type)), raw: values.join(' ') };
}

function ownerHashFromNsec3(owner, apex) {
  const normalized = normalizeName(owner);
  const apexName = normalizeName(apex);
  if (!normalized.endsWith(`.${apexName}`)) return null;
  return normalized.slice(0, -(apexName.length + 1)).toUpperCase();
}

function rrsetFromAnswers(answers, type, owner = null) {
  return (answers || []).filter((answer) => answer.type === type && (!owner || normalizeName(answer.name) === normalizeName(owner)));
}

function findRrsig(answers, owner, covered) {
  return (answers || []).find((answer) => answer.type === 'RRSIG'
    && normalizeName(answer.name) === normalizeName(owner)
    && parseRrsigRdata(answer.data)?.covered === normalizeType(covered));
}

function addCheck(checks, id, title, status, summary, details = []) {
  checks.push({ id, title, status, summary, details });
}

function signatureStatusToCheck(result, label) {
  if (result.status === 'pass') return { status: 'pass', summary: `${label} RRSIG verified cryptographically (${result.method || 'signature valid'}).` };
  if (result.status === 'unsupported') return { status: 'info', summary: `${label} RRSIG present but could not be verified in this browser: ${result.error}` };
  if (result.status === 'missing') return { status: 'fail', summary: `${label} has no RRSIG.` };
  return { status: 'fail', summary: `${label} RRSIG verification failed: ${result.error || result.status}.` };
}

export async function auditDnssec(name, resolver = 'cloudflare', options = {}) {
  const chain = await walkDnssecChain(name, resolver, options);
  if (!chain.ok) return { ok: false, error: chain.error, name: normalizeName(name), resolver, checks: [] };
  const apex = chain.apex;
  const base = { resolver, name: normalizeName(name), apex, chain, checkedAt: new Date().toISOString() };
  if (apex === '.') {
    return {
      ...base,
      ok: true,
      overall: 'unknown',
      checks: [{ id: 'root-apex', title: 'Root zone audit', status: 'info', summary: 'Apex detection returned the root. Pick a specific zone below the root for NSEC3 and denial tests.', details: [] }],
      signatures: [],
      keys: [],
      dsRecords: [],
      denial: null,
      queries: {},
    };
  }

  const queries = {
    soa: await queryDns({ resolver, name: apex, type: 'SOA', dnssec: true, signal: options.signal }),
    ns: await queryDns({ resolver, name: apex, type: 'NS', dnssec: true, signal: options.signal }),
    dnskey: await queryDns({ resolver, name: apex, type: 'DNSKEY', dnssec: true, signal: options.signal }),
    ds: await queryDns({ resolver, name: apex, type: 'DS', dnssec: true, signal: options.signal }),
    nsec3param: await queryDns({ resolver, name: apex, type: 'NSEC3PARAM', dnssec: true, signal: options.signal }),
    nsec: await queryDns({ resolver, name: apex, type: 'NSEC', dnssec: true, signal: options.signal }),
    a: await queryDns({ resolver, name: apex, type: 'A', dnssec: true, signal: options.signal }),
    aaaa: await queryDns({ resolver, name: apex, type: 'AAAA', dnssec: true, signal: options.signal }),
    mx: await queryDns({ resolver, name: apex, type: 'MX', dnssec: true, signal: options.signal }),
    caa: await queryDns({ resolver, name: apex, type: 'CAA', dnssec: true, signal: options.signal }),
    txt: await queryDns({ resolver, name: apex, type: 'TXT', dnssec: true, signal: options.signal }),
  };
  const keys = (queries.dnskey.answers || [])
    .filter((answer) => answer.type === 'DNSKEY')
    .map((answer) => {
      const parsed = parseDnskeyRdata(answer.data);
      return parsed ? { ...parsed, keyTag: dnskeyTag(parsed), data: answer.data } : null;
    })
    .filter(Boolean);
  const randomLabel = `audit-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  const randomName = normalizeName(`${randomLabel}.${apex.replace(/\.$/, '')}`);
  const denialQuery = await queryDns({ resolver, name: randomName, type: 'A', dnssec: true, signal: options.signal });
  queries.denial = denialQuery;

  const nsec3Param = (queries.nsec3param.answers || []).map((answer) => parseNsec3Param(answer.data)).find(Boolean) || null;
  const denialAuthority = denialQuery.authority || [];
  const authorityNsec3 = denialAuthority.filter((answer) => answer.type === 'NSEC3').map((answer) => ({ ...parseNsec3(answer.data), owner: normalizeName(answer.name), record: answer })).filter((item) => item.hashAlgorithm !== undefined);
  const authorityNsec = denialAuthority.filter((answer) => answer.type === 'NSEC').map((answer) => ({ ...parseNsec(answer.data), owner: normalizeName(answer.name), record: answer })).filter((item) => item.next);
  const usesNsec3 = Boolean(nsec3Param) || authorityNsec3.length > 0;
  const usesNsec = !usesNsec3 && authorityNsec.length > 0;
  const mode = usesNsec3 ? 'NSEC3' : usesNsec ? 'NSEC' : 'none';

  let hash = null;
  let exactNsec3 = null;
  let exactNsec3Query = null;
  if (usesNsec3) {
    const param = nsec3Param || (authorityNsec3[0] ? { hashAlgorithm: authorityNsec3[0].hashAlgorithm, iterations: authorityNsec3[0].iterations, salt: authorityNsec3[0].salt, flags: authorityNsec3[0].flags } : null);
    if (param) {
      hash = await nsec3Hash(randomName, param.salt, param.iterations, param.hashAlgorithm);
      if (hash.ok) {
        exactNsec3Query = await queryDns({ resolver, name: `${hash.base32}.${apex}`, type: 'NSEC3', dnssec: true, signal: options.signal });
        exactNsec3 = (exactNsec3Query.answers || []).filter((answer) => answer.type === 'NSEC3').map((answer) => ({ ...parseNsec3(answer.data), owner: normalizeName(answer.name), record: answer })).find(Boolean) || null;
      }
    }
  }

  const checks = [];
  const dsRecords = (queries.ds.answers || []).filter((answer) => answer.type === 'DS').map((answer) => parseDsRdata(answer.data)).filter(Boolean);
  addCheck(checks, 'chain', 'Chain of trust', chain.overall === 'secure' ? 'pass' : chain.overall === 'insecure' ? 'warn' : 'fail', `Resolver chain status: ${chain.overall}. ${chain.chain.length} level(s) checked.`, chain.chain.map((step) => `${step.zone}: ${step.status}`));

  if (!keys.length) {
    addCheck(checks, 'dnskey', 'DNSKEY present', dsRecords.length ? 'fail' : 'info', dsRecords.length ? 'The parent publishes a DS but no DNSKEY was returned at the apex: the delegation is bogus.' : 'No DNSKEY records were returned. This is an unsigned or insecure delegation.');
  } else {
    const modern = keys.filter((key) => [8, 10, 13, 14, 15].includes(key.algorithm));
    const weak = keys.filter((key) => [1, 3, 5, 6, 7, 12, 16, 17].includes(key.algorithm));
    addCheck(checks, 'dnskey', 'DNSKEY present', 'pass', `${keys.length} DNSKEY record(s): ${keys.map((key) => `${key.keyTag}/${algorithmInfo(key.algorithm).name}/${key.flags === 257 ? 'KSK' : 'ZSK'}`).join(', ')}.`, keys.map((key) => `${key.flags} ${key.protocol} ${key.algorithm} ${key.publicKey.slice(0, 48)}…`));
    addCheck(checks, 'dnskey-algorithms', 'DNSKEY algorithms', weak.length ? 'warn' : modern.length ? 'pass' : 'info', weak.length ? `Legacy algorithm(s) present: ${weak.map((key) => algorithmInfo(key.algorithm).name).join(', ')}.` : `Modern algorithm(s): ${Array.from(new Set(keys.map((key) => algorithmInfo(key.algorithm).name))).join(', ')}.`);
    addCheck(checks, 'dnskey-flags', 'DNSKEY flags and protocol', keys.every((key) => key.protocol === 3 && (key.flags & 0x0100)) ? 'pass' : 'fail', keys.every((key) => key.protocol === 3 && (key.flags & 0x0100)) ? 'All keys use protocol 3 and have the zone-key bit.' : 'At least one key has protocol other than 3 or lacks the zone-key bit.');
  }

  if (dsRecords.length) {
    const dsInfo = dsRecords.map((ds) => `${ds.keyTag}/${algorithmInfo(ds.algorithm).name}/${digestInfo(ds.digestType).name}`).join(', ');
    addCheck(checks, 'ds', 'DS in parent', dsRecords.some((ds) => ds.digestType === 2) ? 'pass' : 'warn', `Parent DS: ${dsInfo}.`, dsRecords.map((ds) => ds.digest));
    const weakDs = dsRecords.filter((ds) => [1, 3, 5, 6, 7, 12, 16, 17].includes(ds.algorithm) || ds.digestType === 1 || ds.digestType === 3);
    addCheck(checks, 'ds-algorithms', 'DS algorithms and digest', weakDs.length ? 'warn' : 'pass', weakDs.length ? 'At least one DS uses a legacy algorithm or digest type.' : 'DS uses a modern algorithm/digest combination.');
  } else {
    addCheck(checks, 'ds', 'DS in parent', 'warn', 'No DS records were returned. The delegation is insecure unless another trust path exists.');
  }

  const signatures = [];
  const verifyTargets = [
    ['dnskey', 'DNSKEY'],
    ['soa', 'SOA'],
    ['ns', 'NS'],
    ['nsec3param', 'NSEC3PARAM'],
    ['nsec', 'NSEC'],
    ['a', 'A'],
    ['aaaa', 'AAAA'],
    ['mx', 'MX'],
    ['caa', 'CAA'],
    ['txt', 'TXT'],
  ];
  if (keys.length) {
    for (const [queryName, type] of verifyTargets) {
      const query = queries[queryName];
      const rrset = rrsetFromAnswers(query.answers, type, apex);
      if (!rrset.length) continue;
      const rrsig = findRrsig(query.answers, apex, type);
      const result = await verifyRrsetSignature({ owner: apex, type, records: rrset, rrsig: rrsig?.data, keys });
      signatures.push({ owner: apex, type, ...result, query: queryName });
      const check = signatureStatusToCheck(result, type);
      addCheck(checks, `sig-${type.toLowerCase()}`, `${type} signature`, check.status, check.summary);
    }
  } else {
    addCheck(checks, 'signatures', 'RRSIG cryptographic verification', chain.overall === 'insecure' ? 'info' : 'fail', chain.overall === 'insecure' ? 'No DNSKEY means there is no local DNSSEC signature to verify; the delegation is insecure.' : 'No DNSKEY was available to verify RRSIGs.');
  }

  // Verify the DS RRset with the parent zone's DNSKEYs. DS is signed by the
  // parent, not by the child; this is the part DNSViz shows as a delegation
  // signature.
  if (dsRecords.length && apex !== '.') {
    const parentZone = parentName(apex);
    const parentStep = chain.chain.find((step) => step.zone === parentZone);
    const parentKeys = (parentStep?.dnskeyRecords || [])
      .map((answer) => {
        const parsed = parseDnskeyRdata(answer.data);
        return parsed ? { ...parsed, keyTag: dnskeyTag(parsed), data: answer.data } : null;
      })
      .filter(Boolean);
    if (parentKeys.length) {
      const dsRrset = rrsetFromAnswers(queries.ds.answers, 'DS', apex);
      const dsRrsig = findRrsig(queries.ds.answers, apex, 'DS');
      const result = await verifyRrsetSignature({ owner: apex, type: 'DS', records: dsRrset, rrsig: dsRrsig?.data, keys: parentKeys });
      signatures.push({ owner: apex, type: 'DS', ...result, query: 'ds' });
      const check = signatureStatusToCheck(result, `DS (signed by ${parentZone})`);
      addCheck(checks, 'sig-ds', 'DS signature (parent)', check.status, check.summary);
    } else {
      addCheck(checks, 'sig-ds', 'DS signature (parent)', 'info', `No parent DNSKEY evidence was available for ${parentZone}; the DS digest match was still checked by the chain walk.`);
    }
  }

  // Verify NSEC3/NSEC RRsets from the denial authority with the zone keys.
  for (const item of authorityNsec3.slice(0, 3)) {
    const rrsig = findRrsig(denialAuthority, item.owner, 'NSEC3');
    const result = await verifyRrsetSignature({ owner: item.owner, type: 'NSEC3', records: [item.record], rrsig: rrsig?.data, keys });
    signatures.push({ owner: item.owner, type: 'NSEC3', ...result, query: 'denial' });
  }
  for (const item of authorityNsec.slice(0, 3)) {
    const rrsig = findRrsig(denialAuthority, item.owner, 'NSEC');
    const result = await verifyRrsetSignature({ owner: item.owner, type: 'NSEC', records: [item.record], rrsig: rrsig?.data, keys });
    signatures.push({ owner: item.owner, type: 'NSEC', ...result, query: 'denial' });
  }
  const failedSignatures = signatures.filter((item) => ['fail', 'no-key', 'missing'].includes(item.status));
  const verifiedSignatures = signatures.filter((item) => item.status === 'pass');
  const unsupportedSignatures = signatures.filter((item) => item.status === 'unsupported');
  if (signatures.length) {
    addCheck(checks, 'signatures', 'RRSIG cryptographic verification',
      failedSignatures.length ? 'fail' : verifiedSignatures.length ? 'pass' : 'info',
      `${verifiedSignatures.length} verified, ${failedSignatures.length} failed, ${unsupportedSignatures.length} unsupported of ${signatures.length} checked RRset(s).`,
      failedSignatures.map((item) => `${item.owner} ${item.type}: ${item.error || item.status}`));
  }

  for (const [label, query] of Object.entries(queries)) {
    if (label === 'ds') continue; // DS is signed by the parent; the chain check covers it.
    for (const answer of (query.answers || []).filter((item) => item.type === 'RRSIG')) {
      const rrsig = parseRrsigRdata(answer.data);
      if (!rrsig) continue;
      const now = Math.floor(Date.now() / 1000);
      if (rrsig.expiration !== null && rrsig.expiration < now) {
        addCheck(checks, `rrsig-expired-${answer.name}-${rrsig.covered}`, `RRSIG expiry for ${rrsig.covered}`, 'fail', `Expired at ${new Date(rrsig.expiration * 1000).toISOString()}.`);
      } else if (rrsig.expiration !== null && rrsig.expiration - now < 86400) {
        addCheck(checks, `rrsig-expiring-${answer.name}-${rrsig.covered}`, `RRSIG expiry for ${rrsig.covered}`, 'warn', `Expires in ${Math.floor((rrsig.expiration - now) / 86400)} day(s).`);
      }
      if (rrsig.signer !== apex) {
        addCheck(checks, `rrsig-signer-${answer.name}-${rrsig.covered}`, `RRSIG signer for ${rrsig.covered}`, 'warn', `Signer is ${rrsig.signer}, expected ${apex}.`);
      }
      if (keys.length && !keys.some((key) => key.keyTag === rrsig.keyTag && key.algorithm === rrsig.algorithm)) {
        addCheck(checks, `rrsig-key-${answer.name}-${rrsig.covered}`, `RRSIG key for ${rrsig.covered}`, 'fail', `No published DNSKEY matches key tag ${rrsig.keyTag} and algorithm ${rrsig.algorithm}.`);
      }
    }
  }

  // NSEC3PARAM / NSEC3 tests.
  if (usesNsec3) {
    const params = nsec3Param || (authorityNsec3[0] ? {
      hashAlgorithm: authorityNsec3[0].hashAlgorithm,
      flags: authorityNsec3[0].flags,
      iterations: authorityNsec3[0].iterations,
      salt: authorityNsec3[0].salt,
      raw: 'inferred from NSEC3',
    } : null);
    if (!params) {
      addCheck(checks, 'nsec3param', 'NSEC3PARAM', 'fail', 'NSEC3 records are in use but no NSEC3PARAM record was found at the apex.');
    } else {
      const paramPass = params.hashAlgorithm === 1 && params.iterations <= 100 && params.flags === 0;
      addCheck(checks, 'nsec3param', 'NSEC3PARAM', paramPass ? (params.iterations === 0 ? 'pass' : 'warn') : 'warn',
        `NSEC3PARAM ${params.raw}: hash algorithm ${params.hashAlgorithm}, iterations ${params.iterations}, salt ${params.salt}, flags ${params.flags}.`,
        [params.hashAlgorithm === 1 ? 'SHA-1 is the standard NSEC3 hash algorithm.' : 'Only SHA-1 / algorithm 1 is supported by this audit.', params.iterations === 0 ? 'Zero iterations is the modern recommendation (RFC 9276).' : 'Iterations increase CPU cost; RFC 9276 recommends 0 for new deployments.']);
      if (hash?.ok) {
        addCheck(checks, 'nsec3-hash', 'NSEC3 hash computation', exactNsec3 ? 'pass' : 'info', `Hashed random name ${randomName}: ${hash.base32}.`, [`NSEC3 owner queried: ${hash.base32}.${apex}`]);
        if (exactNsec3) {
          const consistent = exactNsec3.hashAlgorithm === params.hashAlgorithm
            && exactNsec3.iterations === params.iterations
            && exactNsec3.salt === params.salt
            && exactNsec3.flags === params.flags;
          const ownerHash = ownerHashFromNsec3(exactNsec3.owner, apex);
          addCheck(checks, 'nsec3-exact', 'Exact NSEC3 record', ownerHash === hash.base32 && consistent ? 'pass' : 'fail',
            `NSEC3 at ${exactNsec3.owner} has next ${exactNsec3.nextHashed}; parameters ${consistent ? 'match' : 'do not match'} NSEC3PARAM.`);
          if (exactNsec3Query?.flags?.ad) {
            addCheck(checks, 'nsec3-ad', 'Exact NSEC3 authenticated', 'pass', 'The resolver set AD for the exact NSEC3 query.');
          } else {
            addCheck(checks, 'nsec3-ad', 'Exact NSEC3 authenticated', 'warn', 'The resolver did not set AD for the exact NSEC3 query.');
          }
        }
      } else {
        addCheck(checks, 'nsec3-hash', 'NSEC3 hash computation', 'info', hash?.error || 'NSEC3 hash could not be computed.');
      }
      const covering = authorityNsec3.find((item) => nsec3Covers(ownerHashFromNsec3(item.owner, apex), item.nextHashed, hash?.base32 || ''));
      addCheck(checks, 'nsec3-denial', 'NSEC3 denial proof',
        covering ? 'pass' : 'fail',
        covering ? `NSEC3 ${covering.owner} covers the random name hash ${hash?.base32 || '?'}; resolver AD=${Boolean(denialQuery.flags?.ad)} (AD on negative answers is resolver-dependent; confirm with dig/delv).` : 'No NSEC3 record in the authority section covers the random name hash.',
        authorityNsec3.map((item) => `${item.owner} → ${item.nextHashed} (${item.hashAlgorithm}/${item.iterations}/${item.salt})`));
      addCheck(checks, 'denial-rcode', 'NXDOMAIN/NODATA behavior', denialQuery.rcode === 'NXDOMAIN' ? 'pass' : denialQuery.rcode === 'NOERROR' ? 'info' : 'warn', `Random non-existent name returned ${denialQuery.rcode}.`);
    }
  } else if (usesNsec) {
    const covering = authorityNsec.find((item) => nsecCovers(item.owner, item.next, randomName));
    addCheck(checks, 'nsec', 'NSEC denial proof', covering ? 'pass' : 'fail',
      covering ? `${covering.owner} covers ${randomName} up to ${covering.next}; resolver AD=${Boolean(denialQuery.flags?.ad)} (AD on negative answers is resolver-dependent; confirm with dig/delv).` : 'No NSEC record in the authority section covers the random name.',
      authorityNsec.map((item) => `${item.owner} → ${item.next}`));
    addCheck(checks, 'denial-rcode', 'NXDOMAIN/NODATA behavior', denialQuery.rcode === 'NXDOMAIN' ? 'pass' : denialQuery.rcode === 'NOERROR' ? 'info' : 'warn', `Random non-existent name returned ${denialQuery.rcode}.`);
  } else {
    addCheck(checks, 'denial', 'Denial of existence', chain.overall === 'insecure' ? 'info' : 'warn', 'No NSEC3PARAM, NSEC3 or NSEC records were found in the authority section for the random name. The zone may be unsigned or the resolver may not return DNSSEC proof records.');
  }

  // AD coverage for the core answers.
  const adQueries = ['dnskey', 'soa', 'ns', 'nsec3param'].filter((key) => queries[key]?.ok && queries[key].answers?.length);
  const adSet = adQueries.filter((key) => queries[key].flags?.ad);
  if (adQueries.length) {
    const adStatus = chain.overall === 'insecure' ? 'info' : adSet.length === adQueries.length ? 'pass' : adSet.length ? 'warn' : 'fail';
    addCheck(checks, 'ad', 'Resolver authenticated data', adStatus, `${adSet.length}/${adQueries.length} core queries had AD set (${adQueries.join(', ')}).`);
  }

  const overall = chain.overall === 'insecure'
    ? 'insecure'
    : failedSignatures.length || chain.overall === 'bogus' || checks.some((check) => check.id === 'nsec3-denial' && check.status === 'fail') || checks.some((check) => check.id === 'nsec' && check.status === 'fail')
      ? 'bogus'
      : checks.some((check) => check.status === 'fail')
        ? 'review'
        : 'secure';

  return {
    ...base,
    ok: true,
    overall,
    checks,
    signatures,
    denial: {
      mode,
      randomName,
      query: denialQuery,
      nsec3param: nsec3Param,
      hash: hash?.ok ? { base32: hash.base32, bytes: bytesToHex(hash.bytes), salt: hash.salt ? bytesToHex(hash.salt) : '-' } : hash,
      exactNsec3,
      exactNsec3Query,
      authorityNsec3,
      authorityNsec,
    },
    keys,
    dsRecords,
    queries,
  };
}

export function auditDigCommands(audit, resolver = 'cloudflare') {
  const server = resolver === 'google' ? '8.8.8.8' : '1.1.1.1';
  const apex = audit.apex;
  const commands = [
    `dig @${server} ${apex} DNSKEY +dnssec +multi`,
    `dig @${server} ${apex} DS +dnssec +multi`,
    `dig @${server} ${apex} SOA +dnssec +multi`,
    `dig @${server} ${apex} NSEC3PARAM +dnssec +multi`,
    `dig @${server} ${apex} A +dnssec +multi`,
    `dig @${server} ${apex} AAAA +dnssec +multi`,
    `dig @${server} ${apex} MX +dnssec +multi`,
    `dig @${server} ${apex} TXT +dnssec +multi`,
    `dig @${server} ${apex} NSEC +dnssec +multi`,
    `dig @${server} ${audit.denial?.randomName || `random.${apex}`} A +dnssec +comments`,
  ];
  if (audit.denial?.hash?.base32) commands.push(`dig @${server} ${audit.denial.hash.base32}.${apex} NSEC3 +dnssec +multi`);
  commands.push(`delv @${server} ${apex} DNSKEY +rtrace`);
  commands.push(`dig +trace ${apex} DNSKEY +dnssec`);
  return commands;
}
