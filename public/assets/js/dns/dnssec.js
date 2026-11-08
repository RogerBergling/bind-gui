/* DNSSEC key-tag, DS digest, offline matching and online chain inspection. */

import { base64ToBytes, bytesToHex, concatBytes, shellQuote } from '../utils.js';
import { labelsOf, nameToWire, normalizeName, parentName } from './names.js';
import { parseDnssecTime } from './syntax.js';
import { algorithmInfo, digestInfo } from './types.js';
import { queryDns } from './doh.js';

export function parseDnskeyRdata(input) {
  if (!input) return null;
  if (typeof input === 'object' && 'flags' in input && 'publicKey' in input) {
    return {
      flags: Number(input.flags),
      protocol: Number(input.protocol),
      algorithm: Number(input.algorithm),
      publicKey: String(input.publicKey),
    };
  }
  let text = String(input).trim().replace(/^(CDNSKEY|DNSKEY)\s+/i, '');
  const parts = text.split(/\s+/);
  if (parts.length < 4) return null;
  return {
    flags: Number(parts[0]),
    protocol: Number(parts[1]),
    algorithm: Number(parts[2]),
    publicKey: parts.slice(3).join(''),
  };
}

export function dnskeyRdataBytes(key) {
  const parsed = parseDnskeyRdata(key);
  if (!parsed) return null;
  try {
    const publicKey = base64ToBytes(parsed.publicKey);
    const header = Uint8Array.of(
      (parsed.flags >> 8) & 0xff,
      parsed.flags & 0xff,
      parsed.protocol & 0xff,
      parsed.algorithm & 0xff,
    );
    return concatBytes(header, publicKey);
  } catch {
    return null;
  }
}

/** RFC 4034 Appendix B key tag. */
export function dnskeyTag(input) {
  const bytes = dnskeyRdataBytes(input);
  if (!bytes) return null;
  let accumulator = 0;
  for (let index = 0; index < bytes.length; index += 1) {
    accumulator += (index & 1) ? bytes[index] : bytes[index] << 8;
  }
  accumulator += (accumulator >> 16) & 0xffff;
  return accumulator & 0xffff;
}

export function parseDsRdata(input) {
  if (!input) return null;
  if (typeof input === 'object' && 'keyTag' in input) {
    return {
      keyTag: Number(input.keyTag),
      algorithm: Number(input.algorithm),
      digestType: Number(input.digestType),
      digest: String(input.digest).toUpperCase(),
    };
  }
  let text = String(input).trim().replace(/^(CDS|DS)\s+/i, '');
  const parts = text.split(/\s+/);
  if (parts.length < 4) return null;
  return {
    keyTag: Number(parts[0]),
    algorithm: Number(parts[1]),
    digestType: Number(parts[2]),
    digest: parts.slice(3).join('').toUpperCase(),
  };
}

export function parseRrsigRdata(input) {
  if (!input) return null;
  if (typeof input === 'object' && 'covered' in input) return input;
  const text = String(input).trim().replace(/^RRSIG\s+/i, '');
  const parts = text.split(/\s+/);
  if (parts.length < 9) return null;
  return {
    covered: parts[0].toUpperCase(),
    algorithm: Number(parts[1]),
    labels: Number(parts[2]),
    originalTTL: Number(parts[3]),
    expiration: parseDnssecTime(parts[4]),
    inception: parseDnssecTime(parts[5]),
    keyTag: Number(parts[6]),
    signer: normalizeName(parts[7]),
    signature: parts.slice(8).join(''),
    expirationRaw: parts[4],
    inceptionRaw: parts[5],
  };
}

function digestAlgorithmName(type) {
  return { 1: 'SHA-1', 2: 'SHA-256', 3: 'GOST R 34.11-94', 4: 'SHA-384' }[Number(type)] || null;
}

export async function dsDigest(owner, dnskey, digestType) {
  const algorithm = digestAlgorithmName(digestType);
  if (!algorithm) return { ok: false, error: `Unsupported digest type ${digestType}.` };
  if (Number(digestType) === 3) {
    return { ok: false, error: 'GOST R 34.11-94 is not available in Web Crypto; verify this DS with delv or named-checkds.' };
  }
  if (!globalThis.crypto?.subtle) {
    return { ok: false, error: 'Web Crypto is unavailable, so the DS digest cannot be recomputed.' };
  }
  const rdata = dnskeyRdataBytes(dnskey);
  if (!rdata) return { ok: false, error: 'The DNSKEY public key is not valid base64.' };
  try {
    const input = concatBytes(nameToWire(owner), rdata);
    const hash = await crypto.subtle.digest(algorithm, input);
    return { ok: true, digest: bytesToHex(new Uint8Array(hash)).toUpperCase(), algorithm };
  } catch (error) {
    return { ok: false, error: error?.message || 'Could not compute the DS digest.' };
  }
}

export async function matchDsToDnskeys(owner, dsRecords, dnskeyRecords) {
  const dsList = (dsRecords || []).map((record) => parseDsRdata(record?.data ?? record)).filter(Boolean);
  const keys = (dnskeyRecords || []).map((record) => {
    const parsed = parseDnskeyRdata(record?.data ?? record);
    return parsed ? { ...parsed, keyTag: dnskeyTag(parsed), record } : null;
  }).filter(Boolean);
  const results = [];
  for (const ds of dsList) {
    const candidates = keys.filter((key) => key.algorithm === ds.algorithm && key.keyTag === ds.keyTag);
    const computed = [];
    if (candidates.length === 0) {
      results.push({
        ds,
        status: 'no-key',
        algorithm: algorithmInfo(ds.algorithm),
        digestInfo: digestInfo(ds.digestType),
        candidates: [],
        computed,
      });
      continue;
    }
    for (const key of candidates) {
      const digest = await dsDigest(owner, key, ds.digestType);
      computed.push({ key, ...digest, matches: digest.ok && digest.digest === ds.digest });
    }
    const matched = computed.some((entry) => entry.matches);
    results.push({
      ds,
      status: matched ? 'match' : 'mismatch',
      algorithm: algorithmInfo(ds.algorithm),
      digestInfo: digestInfo(ds.digestType),
      candidates,
      computed,
    });
  }
  return {
    owner: normalizeName(owner),
    ds: dsList,
    keys,
    results,
    hasDs: dsList.length > 0,
    hasKeys: keys.length > 0,
    matched: results.some((entry) => entry.status === 'match'),
    status: dsList.length === 0
      ? (keys.length ? 'keys-without-ds' : 'unsigned')
      : (results.some((entry) => entry.status === 'match') ? 'match' : 'bogus'),
  };
}

export function zoneDnssecInventory(zone) {
  const records = zone?.records || [];
  const byType = (type) => records.filter((record) => record.type === type);
  const keys = byType('DNSKEY');
  const ds = [...byType('DS'), ...byType('CDS')];
  const rrsigs = byType('RRSIG');
  const nsec = byType('NSEC');
  const nsec3 = byType('NSEC3');
  const nsec3param = byType('NSEC3PARAM');
  return {
    keys,
    ds,
    cds: byType('CDS'),
    cdnskey: byType('CDNSKEY'),
    rrsigs,
    nsec,
    nsec3,
    nsec3param,
    signed: rrsigs.length > 0,
    hasKeys: keys.length > 0,
    hasDs: ds.length > 0,
    denial: nsec3.length ? 'NSEC3' : (nsec.length ? 'NSEC' : 'none'),
  };
}

export function rrsigHealth(zone, now = Date.now()) {
  const inventory = zoneDnssecInventory(zone);
  const findings = [];
  const nowSeconds = Math.floor(now / 1000);
  for (const record of inventory.rrsigs) {
    const parsed = parseRrsigRdata(record.data ?? record.rdata);
    if (!parsed) continue;
    if (parsed.expiration !== null && parsed.expiration < nowSeconds) {
      findings.push({ severity: 'error', record, parsed, message: `RRSIG for ${parsed.covered} expired ${new Date(parsed.expiration * 1000).toISOString()}.` });
    } else if (parsed.expiration !== null && parsed.expiration - nowSeconds < 30 * 86400) {
      findings.push({ severity: 'warning', record, parsed, message: `RRSIG for ${parsed.covered} expires in ${Math.max(0, Math.floor((parsed.expiration - nowSeconds) / 86400))} days.` });
    }
    if (parsed.inception !== null && parsed.inception > nowSeconds + 3600) {
      findings.push({ severity: 'warning', record, parsed, message: `RRSIG for ${parsed.covered} is not valid until ${new Date(parsed.inception * 1000).toISOString()}.` });
    }
  }
  return findings;
}

export async function findZoneApex(name, resolver = 'cloudflare', options = {}) {
  let candidate = normalizeName(name);
  const maxDepth = labelsOf(candidate).length + 2;
  for (let depth = 0; depth < maxDepth; depth += 1) {
    const result = await queryDns({ resolver, name: candidate, type: 'SOA', dnssec: false, signal: options.signal });
    if (result.ok && result.answers.some((answer) => answer.type === 'SOA')) {
      return { apex: candidate, result };
    }
    if (candidate === '.') break;
    candidate = parentName(candidate);
  }
  return { apex: null, error: 'Could not determine the zone apex from SOA answers.' };
}

/**
 * Walk from a name's zone apex to the root, querying DS and DNSKEY at each
 * delegation. This uses the resolver's own validation result (AD) plus local
 * DS↔DNSKEY digest matching. It does not re-implement RRSIG signature maths.
 */
export async function walkDnssecChain(name, resolver = 'cloudflare', options = {}) {
  const lookup = await findZoneApex(name, resolver, options);
  if (!lookup.apex) {
    return { ok: false, error: lookup.error, name: normalizeName(name), chain: [], resolver };
  }
  const chain = [];
  let current = lookup.apex;
  const seen = new Set();
  let depth = 0;
  while (current && !seen.has(current) && depth < 16) {
    if (options.signal?.aborted) break;
    seen.add(current);
    const [dsResult, dnskeyResult] = await Promise.all([
      queryDns({ resolver, name: current, type: 'DS', dnssec: true, signal: options.signal }),
      queryDns({ resolver, name: current, type: 'DNSKEY', dnssec: true, signal: options.signal }),
    ]);
    const dsRecords = (dsResult.answers || []).filter((answer) => answer.type === 'DS');
    const dnskeyRecords = (dnskeyResult.answers || []).filter((answer) => answer.type === 'DNSKEY');
    const rrsigs = (dnskeyResult.answers || []).filter((answer) => answer.type === 'RRSIG');
    const matching = await matchDsToDnskeys(current, dsRecords, dnskeyRecords);
    const isRoot = current === '.';
    let status;
    if (isRoot) status = 'root';
    else if (!dsResult.ok || !dnskeyResult.ok) status = 'error';
    else if (dsRecords.length === 0) status = 'insecure';
    else if (matching.status === 'match') {
      status = dsResult.flags?.ad && dnskeyResult.flags?.ad ? 'secure' : 'matches-unvalidated';
    } else status = 'bogus';
    chain.push({
      zone: current,
      isRoot,
      dsResult,
      dnskeyResult,
      dsRecords,
      dnskeyRecords,
      rrsigs,
      matching,
      status,
      ad: Boolean(dsResult.flags?.ad || dnskeyResult.flags?.ad),
      keys: matching.keys,
      ds: matching.ds,
    });
    if (isRoot || status === 'insecure' || status === 'bogus' || status === 'error') break;
    current = parentName(current);
    depth += 1;
  }
  const statuses = chain.map((item) => item.status);
  let overall = 'secure';
  if (statuses.includes('bogus') || statuses.includes('error')) overall = 'bogus';
  else if (statuses.includes('insecure')) overall = 'insecure';
  else if (statuses.includes('matches-unvalidated')) overall = 'unvalidated';
  else if (chain.length === 0) overall = 'unknown';
  return {
    ok: true,
    name: normalizeName(name),
    apex: lookup.apex,
    resolver,
    chain,
    overall,
    secure: overall === 'secure',
    checkedAt: new Date().toISOString(),
  };
}

export function chainDigCommands(chain, resolver = 'cloudflare') {
  const server = resolver === 'google' ? '8.8.8.8' : '1.1.1.1';
  const commands = [];
  for (const item of chain || []) {
    commands.push({
      label: `DS for ${item.zone}`,
      command: `dig @${server} ${shellQuote(item.zone)} DS +dnssec +multi`,
      explanation: 'DS lives in the parent zone and commits to a DNSKEY in the child zone.',
    });
    commands.push({
      label: `DNSKEY for ${item.zone}`,
      command: `dig @${server} ${shellQuote(item.zone)} DNSKEY +dnssec +multi`,
      explanation: 'DNSKEY lives at the zone apex. Compare its key tag and digest with the parent DS.',
    });
  }
  return commands;
}

export function keyTagLabel(key) {
  const parsed = parseDnskeyRdata(key);
  if (!parsed) return 'unknown';
  const tag = dnskeyTag(parsed);
  return `${tag ?? '?'} · ${parsed.flags === 257 ? 'KSK/SEP' : (parsed.flags === 256 ? 'ZSK' : `flags ${parsed.flags}`)} · ${algorithmInfo(parsed.algorithm).name}`;
}

export function dnskeyFlagsSummary(flags) {
  const value = Number(flags);
  const parts = [];
  if (value & 1) parts.push('SEP');
  if (value & 2) parts.push('REVOKE');
  if (value & 0x0100) parts.push('ZONE');
  return parts.join(' · ') || 'none';
}

export function zoneUsesManagedSigning(zone) {
  const policy = zone?.options?.get('dnssec-policy')?.[0]?.args?.[0];
  const inline = String(zone?.options?.get('inline-signing')?.[0]?.args?.[0] || '').toLowerCase();
  return Boolean(policy) || inline === 'yes';
}
