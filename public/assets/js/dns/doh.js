/* DNS-over-HTTPS client and dig command builder. */

import { isValidIPv4, isValidIPv6, normalizeName, reverseIpName } from './names.js';
import { normalizeRdataForCompare } from './syntax.js';
import { normalizeType, rcodeName, typeCode, typeName } from './types.js';

export const RESOLVERS = {
  cloudflare: {
    id: 'cloudflare',
    name: 'Cloudflare',
    address: '1.1.1.1',
    endpoint: 'https://cloudflare-dns.com/dns-query',
    digServer: '1.1.1.1',
    description: 'Cloudflare 1.1.1.1 — privacy-focused resolver with DNSSEC validation.',
    docs: 'https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/',
  },
  google: {
    id: 'google',
    name: 'Google Public DNS',
    address: '8.8.8.8',
    endpoint: 'https://dns.google/resolve',
    digServer: '8.8.8.8',
    description: 'Google Public DNS 8.8.8.8 — globally distributed resolver with DNSSEC validation.',
    docs: 'https://developers.google.com/speed/public-dns/docs/doh/json',
  },
};

export function resolverById(id) {
  return RESOLVERS[id] || RESOLVERS.cloudflare;
}

export const RESOLVER_LIST = Object.values(RESOLVERS);

export function normalizeAnswerValue(type, data) {
  const name = normalizeType(type);
  let value = String(data ?? '').trim();
  if (name === 'DNSKEY' || name === 'RRSIG' || name === 'NSEC' || name === 'NSEC3') {
    value = value.replace(new RegExp(`^${name}\\s+`, 'i'), '');
  }
  return normalizeRdataForCompare(name, value);
}

function normalizeDoHAnswer(entry, section) {
  const code = Number(entry.type);
  const type = Number.isFinite(code) ? typeName(code) : normalizeType(entry.type);
  return {
    name: entry.name || '',
    typeCode: code,
    type,
    ttl: Number(entry.TTL ?? entry.ttl ?? 0),
    data: String(entry.data ?? ''),
    section,
  };
}

export function buildDohUrl(resolverId, query) {
  const resolver = resolverById(resolverId);
  const url = new URL(resolver.endpoint);
  url.searchParams.set('name', query.name);
  url.searchParams.set('type', normalizeType(query.type || 'A'));
  url.searchParams.set('do', query.dnssec === false ? 'false' : 'true');
  url.searchParams.set('cd', query.checkingDisabled ? 'true' : 'false');
  return url.toString();
}

export async function queryDns(input) {
  const {
    resolver: resolverInput = 'cloudflare',
    name,
    type = 'A',
    dnssec = true,
    checkingDisabled = false,
    timeoutMs = 9000,
    signal = null,
  } = input || {};
  const resolver = typeof resolverInput === 'string' ? resolverById(resolverInput) : (resolverInput || resolverById('cloudflare'));
  const queryType = normalizeType(type);
  const rawName = String(name ?? '').trim();
  const reverse = normalizeType(type) === 'PTR' && (isValidIPv4(rawName) || isValidIPv6(rawName))
    ? reverseIpName(rawName)
    : null;
  const queryName = reverse || normalizeName(name);
  if (!queryName || queryName === '.') {
    // The root is valid for NS/DNSKEY/SOA queries.
  }
  if (!typeCode(queryType)) {
    throw new Error(`Unknown DNS type “${type}”.`);
  }
  if (queryName.includes('..')) throw new Error('The DNS name contains two consecutive dots.');

  const url = buildDohUrl(resolver.id, { name: queryName, type: queryType, dnssec, checkingDisabled });
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(new Error('DNS query timed out')), Math.max(1000, timeoutMs));
  const abortExternal = () => controller.abort(signal?.reason || new Error('DNS query cancelled'));
  if (signal) {
    if (signal.aborted) abortExternal();
    else signal.addEventListener('abort', abortExternal, { once: true });
  }
  const startedAt = performance.now();
  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: { accept: 'application/dns-json' },
      signal: controller.signal,
      cache: 'no-store',
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
    });
    const elapsedMs = Math.round(performance.now() - startedAt);
    if (!response.ok) {
      return {
        ok: false,
        resolver,
        name: queryName,
        type: queryType,
        url,
        elapsedMs,
        error: `Resolver returned HTTP ${response.status} ${response.statusText || ''}`.trim(),
      };
    }
    const payload = await response.json();
    const answers = (payload.Answer || []).map((entry) => normalizeDoHAnswer(entry, 'answer'));
    const authority = (payload.Authority || []).map((entry) => normalizeDoHAnswer(entry, 'authority'));
    const additional = (payload.Additional || []).map((entry) => normalizeDoHAnswer(entry, 'additional'));
    return {
      ok: true,
      resolver,
      name: queryName,
      type: queryType,
      url,
      elapsedMs,
      status: Number(payload.Status ?? 0),
      rcode: rcodeName(payload.Status ?? 0),
      flags: {
        aa: Boolean(payload.AA),
        tc: Boolean(payload.TC),
        rd: Boolean(payload.RD),
        ra: Boolean(payload.RA),
        ad: Boolean(payload.AD),
        cd: Boolean(payload.CD),
      },
      question: payload.Question || [],
      answers,
      authority,
      additional,
      comment: payload.Comment || payload.comment || null,
      raw: payload,
    };
  } catch (error) {
    const elapsedMs = Math.round(performance.now() - startedAt);
    const message = error?.name === 'AbortError' ? 'The DNS query was cancelled or timed out.' : (error?.message || 'DNS query failed');
    return {
      ok: false,
      resolver,
      name: queryName,
      type: queryType,
      url,
      elapsedMs,
      error: message,
    };
  } finally {
    clearTimeout(timeout);
    if (signal) signal.removeEventListener('abort', abortExternal);
  }
}

export function answerKey(answer) {
  return `${answer.type}|${normalizeAnswerValue(answer.type, answer.data)}`;
}

export function compareDnsResults(left, right, options = {}) {
  const filter = options.filter || ((answer) => !['RRSIG', 'OPT'].includes(answer.type));
  const setA = new Set((left?.answers || []).filter(filter).map(answerKey));
  const setB = new Set((right?.answers || []).filter(filter).map(answerKey));
  const onlyA = Array.from(setA).filter((key) => !setB.has(key));
  const onlyB = Array.from(setB).filter((key) => !setA.has(key));
  const common = Array.from(setA).filter((key) => setB.has(key));
  return {
    consistent: onlyA.length === 0 && onlyB.length === 0,
    onlyA,
    onlyB,
    common,
    adA: Boolean(left?.flags?.ad),
    adB: Boolean(right?.flags?.ad),
    rcodeA: left?.rcode || null,
    rcodeB: right?.rcode || null,
  };
}

export function buildDigCommands({ name, type = 'A', resolver = 'cloudflare', dnssec = true } = {}) {
  const selected = resolverById(resolver);
  const queryType = normalizeType(type);
  const rawName = String(name ?? '').trim();
  const reverse = queryType === 'PTR' && (isValidIPv4(rawName) || isValidIPv6(rawName)) ? reverseIpName(rawName) : null;
  const queryName = reverse || normalizeName(name);
  const server = selected.digServer;
  const dnssecFlag = dnssec ? ' +dnssec' : '';
  const commands = [
    {
      label: 'Primary lookup',
      command: `dig @${server} ${queryName} ${queryType}${dnssecFlag} +multi`,
      explanation: `Ask ${selected.name} (${selected.address}) directly over classic DNS. +multi prints one resource record per line; +dnssec asks for DNSSEC records.`,
    },
    {
      label: 'Short answer',
      command: `dig @${server} ${queryName} ${queryType} +short${dnssecFlag}`,
      explanation: '+short prints only the RDATA. It is convenient for scripts, but it hides flags, authority and DNSSEC status.',
    },
    {
      label: 'See the DNSSEC status',
      command: `dig @${server} ${queryName} ${queryType} +dnssec +comments +stats`,
      explanation: 'The flags line shows qr, rd, ra and ad. The ad (authenticated data) bit means the resolver validated DNSSEC for this answer.',
    },
    {
      label: 'Check the chain',
      command: `dig @${server} ${queryName} DNSKEY +dnssec +multi\n dig @${server} ${queryName} DS +dnssec +multi\n dig @${server} ${queryName} A +dnssec +trace`,
      explanation: 'DNSKEY lives in the zone, DS lives in the parent. +trace follows the delegation from the root, showing where validation could break.',
    },
    {
      label: 'Disable validation (diagnose bogus data)',
      command: `dig @${server} ${queryName} ${queryType} +dnssec +cd +comments`,
      explanation: '+cd sets the Checking Disabled bit. It shows the unvalidated data so you can compare it with the validated answer. Never treat a +cd answer as trustworthy.',
    },
    {
      label: 'Ask the authoritative server',
      command: `dig @ns1.example.com ${queryName} ${queryType} +norecurse +dnssec +multi`,
      explanation: 'Replace ns1.example.com with the zone NS. +norecurse prevents the server from recursing; authoritative servers should answer directly.',
    },
  ];
  if (queryType === 'PTR' || isValidIPv4(rawName) || isValidIPv6(rawName)) {
    commands.unshift({
      label: 'Reverse lookup (-x)',
      command: `dig @${server} -x ${rawName} +dnssec +multi`,
      explanation: '-x automatically converts an IP address into the in-addr.arpa or ip6.arpa name and queries PTR.',
    });
  }
  return commands;
}

export function digTraceCommand(name, type = 'A') {
  return `dig +trace ${normalizeName(name)} ${normalizeType(type)} +dnssec`;
}

export function explainDohLimits() {
  return [
    'A browser cannot open UDP or TCP port 53, so this app uses DNS-over-HTTPS JSON endpoints.',
    'The queried name and type are sent to the selected resolver. Configuration files never leave the browser.',
    'Recursive resolvers return cached answers. TTLs shrink while cached and load-balanced records may differ by location.',
    'DoH JSON is a convenience API, not a replacement for authoritative testing with dig, delv or named-checkzone.',
  ];
}
