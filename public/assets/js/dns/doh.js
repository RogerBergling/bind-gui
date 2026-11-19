/* DNS-over-HTTPS client and dig command builder. */

import { isValidIPv4, isValidIPv6, normalizeName, reverseIpName } from './names.js';
import { shellQuote } from '../utils.js';
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
    custom: false,
  },
  google: {
    id: 'google',
    name: 'Google Public DNS',
    address: '8.8.8.8',
    endpoint: 'https://dns.google/resolve',
    digServer: '8.8.8.8',
    description: 'Google Public DNS 8.8.8.8 — globally distributed resolver with DNSSEC validation.',
    docs: 'https://developers.google.com/speed/public-dns/docs/doh/json',
    custom: false,
  },
};

export const RESOLVER_LIST = Object.values(RESOLVERS);
export const DEFAULT_RESOLVER_ID = 'cloudflare';
export const MAX_CUSTOM_RESOLVERS = 20;

const CUSTOM_ID = /^custom-[a-z0-9][a-z0-9-]{0,79}$/;
const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

function resolverSlug(name) {
  return String(name ?? '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40) || 'resolver';
}

export function customResolverId(name) {
  return `custom-${resolverSlug(name)}-${Date.now().toString(36).slice(-4)}${Math.random().toString(36).slice(2, 6)}`;
}

export function normalizeDohEndpoint(value) {
  let url;
  try {
    url = new URL(String(value ?? '').trim());
  } catch {
    throw new Error('Enter a valid DoH endpoint URL, for example https://dns.example/dns-query.');
  }
  if (url.protocol !== 'https:') {
    throw new Error('The DoH endpoint must use HTTPS. Plain HTTP is not permitted by the app CSP.');
  }
  if (url.username || url.password) {
    throw new Error('Do not embed credentials in the DoH endpoint URL.');
  }
  if (!url.hostname) throw new Error('The DoH endpoint URL needs a hostname.');
  if (url.toString().length > 2048) throw new Error('The DoH endpoint URL is too long.');
  url.hash = '';
  return url.toString();
}

export function normalizeDigServer(value) {
  const raw = String(value ?? '').trim().replace(/\.$/, '');
  if (!raw) throw new Error('Enter a hostname or IP address for dig commands.');
  if (isValidIPv4(raw)) return raw;
  if (isValidIPv6(raw)) return raw.replace(/^\[|\]$/g, '');
  if (raw.length > 253) throw new Error('The dig server hostname is longer than 253 characters.');
  if (!raw.split('.').every((label) => HOST_LABEL.test(label))) {
    throw new Error('The dig server must be a plain hostname or IP address, without shell characters.');
  }
  return raw.toLowerCase();
}

function optionalDigServer(value) {
  try {
    return normalizeDigServer(value);
  } catch {
    return null;
  }
}

export function normalizeCustomResolver(input = {}, options = {}) {
  const name = String(input.name ?? '').trim();
  if (!name) throw new Error('Give the resolver a name.');
  if (name.length > 80) throw new Error('Keep the resolver name under 80 characters.');
  const endpoint = normalizeDohEndpoint(input.endpoint);
  const endpointUrl = new URL(endpoint);
  const address = String(input.address ?? '').trim();
  if (address.length > 120) throw new Error('Keep the address label under 120 characters.');
  const explicitDigServer = String(input.digServer ?? '').trim();
  const digServer = explicitDigServer
    ? normalizeDigServer(explicitDigServer)
    : (optionalDigServer(address) || normalizeDigServer(endpointUrl.hostname));
  let id = String(input.id ?? '').trim().toLowerCase();
  if (!id) {
    if (!options.assignId) throw new Error('The custom resolver id is missing.');
    id = customResolverId(name);
  }
  if (!CUSTOM_ID.test(id)) throw new Error('The custom resolver id is invalid.');
  return {
    id,
    name,
    address: address || endpointUrl.host,
    endpoint,
    digServer,
    description: `Custom DoH JSON resolver at ${endpointUrl.host}.`,
    docs: null,
    custom: true,
  };
}

export function sanitizeCustomResolvers(input) {
  if (!Array.isArray(input)) return [];
  const list = [];
  const seen = new Set();
  for (const item of input) {
    if (!item || typeof item !== 'object') continue;
    try {
      const resolver = normalizeCustomResolver(item);
      if (RESOLVERS[resolver.id] || seen.has(resolver.id)) continue;
      seen.add(resolver.id);
      list.push(resolver);
      if (list.length >= MAX_CUSTOM_RESOLVERS) break;
    } catch {
      /* Invalid local entries are ignored rather than used for a query. */
    }
  }
  return list;
}

export function resolverById(id, customResolvers = []) {
  const key = String(id ?? '').trim();
  if (RESOLVERS[key]) return RESOLVERS[key];
  return sanitizeCustomResolvers(customResolvers).find((resolver) => resolver.id === key)
    || RESOLVERS[DEFAULT_RESOLVER_ID];
}

export function resolverList(customResolvers = []) {
  return [...RESOLVER_LIST, ...sanitizeCustomResolvers(customResolvers)];
}

export function asResolver(input, customResolvers = []) {
  if (input && typeof input === 'object' && input.endpoint) return input;
  return resolverById(input, customResolvers);
}

export function resolverDigServer(input) {
  const resolver = asResolver(input);
  const explicit = String(resolver?.digServer ?? '').trim();
  if (explicit) {
    const normalized = optionalDigServer(explicit);
    if (normalized) return normalized;
  }
  try {
    return normalizeDigServer(new URL(normalizeDohEndpoint(resolver.endpoint)).hostname);
  } catch {
    return RESOLVERS[DEFAULT_RESOLVER_ID].digServer;
  }
}

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
  const resolver = asResolver(resolverId);
  const url = new URL(normalizeDohEndpoint(resolver.endpoint));
  url.searchParams.set('name', query.name);
  url.searchParams.set('type', normalizeType(query.type || 'A'));
  url.searchParams.set('do', query.dnssec === false ? 'false' : 'true');
  url.searchParams.set('cd', query.checkingDisabled ? 'true' : 'false');
  return url.toString();
}

export async function queryDns(input) {
  const {
    resolver: resolverInput = DEFAULT_RESOLVER_ID,
    name,
    type = 'A',
    dnssec = true,
    checkingDisabled = false,
    timeoutMs = 9000,
    signal = null,
  } = input || {};
  const resolver = asResolver(resolverInput);
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

  const startedAt = performance.now();
  let url = '';
  try {
    url = buildDohUrl(resolver, { name: queryName, type: queryType, dnssec, checkingDisabled });
  } catch (error) {
    return {
      ok: false,
      resolver,
      name: queryName,
      type: queryType,
      url,
      elapsedMs: 0,
      error: error?.message || 'The resolver endpoint is invalid.',
    };
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(new Error('DNS query timed out')), Math.max(1000, timeoutMs));
  const abortExternal = () => controller.abort(signal?.reason || new Error('DNS query cancelled'));
  if (signal) {
    if (signal.aborted) abortExternal();
    else signal.addEventListener('abort', abortExternal, { once: true });
  }
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

export function buildDigCommands({ name, type = 'A', resolver = DEFAULT_RESOLVER_ID, dnssec = true } = {}) {
  const selected = asResolver(resolver);
  const queryType = normalizeType(type);
  const rawName = String(name ?? '').trim();
  const reverse = queryType === 'PTR' && (isValidIPv4(rawName) || isValidIPv6(rawName)) ? reverseIpName(rawName) : null;
  const queryName = reverse || normalizeName(name);
  const server = resolverDigServer(selected);
  const dnssecFlag = dnssec ? ' +dnssec' : '';
  const commands = [
    {
      label: 'Primary lookup',
      command: `dig @${server} ${shellQuote(queryName)} ${queryType}${dnssecFlag} +multi`,
      explanation: `Ask ${selected.name} (${selected.address || server}) directly over classic DNS. +multi prints one resource record per line; +dnssec asks for DNSSEC records.`,
    },
    {
      label: 'Short answer',
      command: `dig @${server} ${shellQuote(queryName)} ${queryType} +short${dnssecFlag}`,
      explanation: '+short prints only the RDATA. It is convenient for scripts, but it hides flags, authority and DNSSEC status.',
    },
    {
      label: 'See the DNSSEC status',
      command: `dig @${server} ${shellQuote(queryName)} ${queryType} +dnssec +comments +stats`,
      explanation: 'The flags line shows qr, rd, ra and ad. The ad (authenticated data) bit means the resolver validated DNSSEC for this answer.',
    },
    {
      label: 'Check the chain',
      command: `dig @${server} ${shellQuote(queryName)} DNSKEY +dnssec +multi\n dig @${server} ${shellQuote(queryName)} DS +dnssec +multi\n dig @${server} ${shellQuote(queryName)} A +dnssec +trace`,
      explanation: 'DNSKEY lives in the zone, DS lives in the parent. +trace follows the delegation from the root, showing where validation could break.',
    },
    {
      label: 'Disable validation (diagnose bogus data)',
      command: `dig @${server} ${shellQuote(queryName)} ${queryType} +dnssec +cd +comments`,
      explanation: '+cd sets the Checking Disabled bit. It shows the unvalidated data so you can compare it with the validated answer. Never treat a +cd answer as trustworthy.',
    },
    {
      label: 'Ask the authoritative server',
      command: `dig @ns1.example.com ${shellQuote(queryName)} ${queryType} +norecurse +dnssec +multi`,
      explanation: 'Replace ns1.example.com with the zone NS. +norecurse prevents the server from recursing; authoritative servers should answer directly.',
    },
  ];
  if (queryType === 'PTR' || isValidIPv4(rawName) || isValidIPv6(rawName)) {
    commands.unshift({
      label: 'Reverse lookup (-x)',
      command: `dig @${server} -x ${shellQuote(rawName)} +dnssec +multi`,
      explanation: '-x automatically converts an IP address into the in-addr.arpa or ip6.arpa name and queries PTR.',
    });
  }
  return commands;
}

export function digTraceCommand(name, type = 'A') {
  return `dig +trace ${shellQuote(normalizeName(name))} ${normalizeType(type)} +dnssec`;
}

export function explainDohLimits() {
  return [
    'A browser has no raw UDP/TCP socket API and cannot send a DNS packet to port 53. JavaScript cannot open a classic resolver socket, so this app uses DNS-over-HTTPS JSON endpoints, built in or added as a custom HTTPS endpoint.',
    'The queried name and type are sent to the selected resolver. Configuration files never leave the browser. A custom resolver must support the DoH JSON API and CORS.',
    'Recursive resolvers return cached answers. TTLs shrink while cached and load-balanced records may differ by location.',
    'DoH JSON is a convenience API, not a replacement for authoritative testing with dig, delv or named-checkzone.',
  ];
}
