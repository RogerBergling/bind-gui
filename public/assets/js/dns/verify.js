/* Expected-vs-observed live DNS verification built from imported zone files. */

import { normalizeAnswerValue, queryDns } from './doh.js';
import { isWildcard } from './names.js';
import { normalizeRdataForCompare } from './syntax.js';

const DEFAULT_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'CAA', 'SRV', 'DS', 'DNSKEY'];

const PRIORITY = {
  NS: 1,
  MX: 2,
  TXT: 3,
  A: 4,
  AAAA: 5,
  CNAME: 6,
  CAA: 7,
  SRV: 8,
  DS: 9,
  DNSKEY: 10,
};

export function buildVerificationChecks(zones, options = {}) {
  const {
    types = DEFAULT_TYPES,
    limit = 30,
    includeWildcards = false,
  } = options;
  const typeSet = new Set(types.map((type) => String(type).toUpperCase()));
  const groups = new Map();
  for (const zone of zones || []) {
    for (const record of zone.parsed?.records || []) {
      if (!typeSet.has(record.type)) continue;
      if (record.type === 'SOA') continue;
      if (!includeWildcards && isWildcard(record.owner)) continue;
      if (!record.inZone) continue;
      const key = `${zone.name}|${record.owner}|${record.type}`;
      if (!groups.has(key)) {
        groups.set(key, {
          id: key,
          zone,
          owner: record.owner,
          type: record.type,
          records: [],
          expected: new Set(),
        });
      }
      const check = groups.get(key);
      check.records.push(record);
      check.expected.add(normalizeRdataForCompare(record.type, record.rdata));
    }
  }
  const checks = Array.from(groups.values()).map((check) => {
    const zoneApex = check.zone.name;
    check.isApex = check.owner === zoneApex;
    return check;
  });
  checks.sort((left, right) => {
    if (left.isApex !== right.isApex) return left.isApex ? -1 : 1;
    const leftPriority = PRIORITY[left.type] ?? 50;
    const rightPriority = PRIORITY[right.type] ?? 50;
    if (leftPriority !== rightPriority) return leftPriority - rightPriority;
    return left.owner.localeCompare(right.owner);
  });
  return checks.slice(0, Math.max(1, limit));
}

export function observedValues(result, check) {
  const values = new Set();
  for (const answer of result?.answers || []) {
    if (answer.type !== check.type) continue;
    // A recursive resolver may include a CNAME chain before the requested
    // type. The explicit CNAME check handles that case; compare the RRset here.
    values.add(normalizeAnswerValue(answer.type, answer.data));
  }
  return values;
}

export async function runVerification(checks, options = {}) {
  const {
    resolver = 'cloudflare',
    concurrency = 2,
    signal = null,
    onProgress = null,
  } = options;
  const results = new Array(checks.length);
  let cursor = 0;
  let completed = 0;

  async function worker() {
    while (cursor < checks.length) {
      if (signal?.aborted) return;
      const index = cursor;
      cursor += 1;
      const check = checks[index];
      const result = await queryDns({
        resolver,
        name: check.owner,
        type: check.type,
        dnssec: true,
        signal,
      });
      const observed = observedValues(result, check);
      const missing = Array.from(check.expected).filter((value) => !observed.has(value));
      const unexpected = Array.from(observed).filter((value) => !check.expected.has(value));
      let status;
      if (!result.ok) status = 'error';
      else if (result.rcode === 'NXDOMAIN') status = 'nxdomain';
      else if (result.answers.length === 0) status = 'empty';
      else if (missing.length === 0 && unexpected.length === 0) status = 'match';
      else status = 'mismatch';
      results[index] = {
        check,
        result,
        observed,
        missing,
        unexpected,
        status,
        ttl: result.answers?.[0]?.ttl ?? null,
        ad: Boolean(result.flags?.ad),
        rcode: result.rcode,
        elapsedMs: result.elapsedMs,
      };
      completed += 1;
      onProgress?.({ completed, total: checks.length, result: results[index] });
    }
  }

  const workers = Array.from({ length: Math.min(Math.max(1, concurrency), 4) }, () => worker());
  await Promise.all(workers);
  return results.filter(Boolean);
}

export function summarizeVerification(results) {
  const summary = {
    total: results.length,
    match: 0,
    mismatch: 0,
    nxdomain: 0,
    empty: 0,
    error: 0,
    authenticated: 0,
  };
  for (const result of results) {
    if (result.status in summary) summary[result.status] += 1;
    if (result.ad) summary.authenticated += 1;
  }
  return summary;
}

export function expectedDisplay(check) {
  return Array.from(check.expected).sort();
}

export function resultTone(status) {
  if (status === 'match') return 'ok';
  if (status === 'mismatch' || status === 'nxdomain') return 'danger';
  if (status === 'empty') return 'warn';
  return 'danger';
}

export function verificationCaveats() {
  return [
    'A resolver answer is a cached, location-dependent view. GeoDNS, anycast, round-robin pools and split-horizon views can legitimately return different records.',
    'TTL values shrink in cache and are not compared. A missing record can simply mean the old answer is still cached or the change has not propagated.',
    'DNSSEC-authenticated (AD) means the resolver validated the answer. It does not prove that the data matches your intended change.',
    'For authoritative truth, query the zone’s own nameservers with dig +norecurse and run named-checkzone on the exact file you deploy.',
  ];
}
