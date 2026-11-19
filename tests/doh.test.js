import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildDigCommands,
  buildDohUrl,
  compareDnsResults,
  customResolverId,
  normalizeAnswerValue,
  normalizeCustomResolver,
  queryDns,
  resolverById,
  resolverList,
  sanitizeCustomResolvers,
} from '../public/assets/js/dns/doh.js';

test('builds a Cloudflare DoH URL with DNSSEC and CD flags', () => {
  const url = new URL(buildDohUrl('cloudflare', { name: 'www.example.com.', type: 'A', dnssec: true, checkingDisabled: false }));
  assert.equal(url.origin, 'https://cloudflare-dns.com');
  assert.equal(url.pathname, '/dns-query');
  assert.equal(url.searchParams.get('name'), 'www.example.com.');
  assert.equal(url.searchParams.get('type'), 'A');
  assert.equal(url.searchParams.get('do'), 'true');
  assert.equal(url.searchParams.get('cd'), 'false');
});

test('builds a Google DoH URL', () => {
  const url = new URL(buildDohUrl('google', { name: 'example.com', type: 'MX', dnssec: false, checkingDisabled: true }));
  assert.equal(url.origin, 'https://dns.google');
  assert.equal(url.pathname, '/resolve');
  assert.equal(url.searchParams.get('do'), 'false');
  assert.equal(url.searchParams.get('cd'), 'true');
});

test('normalises TXT, A and DNSKEY answer values', () => {
  assert.equal(normalizeAnswerValue('TXT', '"a" "b"'), '["a","b"]');
  assert.equal(normalizeAnswerValue('A', '192.000.002.001'), '192.0.2.1');
  assert.match(normalizeAnswerValue('DNSKEY', 'DNSKEY 257 3 13 abc'), /^257 3 13/);
  assert.equal(normalizeAnswerValue('CNAME', 'Target.Example.'), 'target.example.');
});

test('compares answers from two resolvers ignoring order and TTL', () => {
  const left = { ok: true, rcode: 'NOERROR', flags: { ad: true }, answers: [{ type: 'A', data: '192.0.2.1', ttl: 60 }, { type: 'A', data: '192.0.2.2', ttl: 60 }] };
  const right = { ok: true, rcode: 'NOERROR', flags: { ad: false }, answers: [{ type: 'A', data: '192.0.2.2', ttl: 10 }, { type: 'A', data: '192.0.2.1', ttl: 10 }] };
  const result = compareDnsResults(left, right);
  assert.equal(result.consistent, true);
  assert.equal(result.onlyA.length, 0);
  assert.equal(result.onlyB.length, 0);
  assert.equal(result.adA, true);
  assert.equal(result.adB, false);
});

test('generates dig commands with resolver and DNSSEC flags', () => {
  const commands = buildDigCommands({ name: 'example.com', type: 'A', resolver: 'google', dnssec: true });
  assert.ok(commands.length >= 5);
  assert.ok(commands[0].command.includes('@8.8.8.8'));
  assert.ok(commands[0].command.includes('+dnssec'));
  assert.ok(commands.some((item) => item.command.includes('+cd')));
});

test('converts an IP PTR lookup to the reverse name and -x command', async () => {
  // queryDns would perform network I/O; the reverse conversion is covered by
  // the command builder, which is deterministic.
  const commands = buildDigCommands({ name: '192.0.2.80', type: 'PTR', resolver: 'cloudflare', dnssec: true });
  assert.ok(commands.some((item) => item.command.includes('80.2.0.192.in-addr.arpa.')));
  assert.ok(commands.some((item) => item.command.includes("-x '192.0.2.80'")));
});

test('accepts and lists a custom HTTPS DoH JSON resolver', () => {
  const resolver = normalizeCustomResolver({
    id: 'custom-home-adguard',
    name: 'Home AdGuard',
    endpoint: 'https://dns.home.example/dns-query?profile=home',
    address: '192.0.2.10',
    digServer: '192.0.2.10',
  });
  assert.equal(resolver.custom, true);
  assert.equal(resolver.digServer, '192.0.2.10');
  assert.equal(resolverList([resolver]).length, 3);
  assert.equal(resolverById('custom-home-adguard', [resolver]).name, 'Home AdGuard');

  const url = new URL(buildDohUrl(resolver, { name: 'example.com.', type: 'A', dnssec: true, checkingDisabled: false }));
  assert.equal(url.origin, 'https://dns.home.example');
  assert.equal(url.pathname, '/dns-query');
  assert.equal(url.searchParams.get('profile'), 'home');
  assert.equal(url.searchParams.get('name'), 'example.com.');
  assert.equal(url.searchParams.get('type'), 'A');
  assert.equal(url.searchParams.get('do'), 'true');

  const commands = buildDigCommands({ name: 'example.com', type: 'A', resolver });
  assert.ok(commands[0].command.includes('@192.0.2.10'));
});

test('derives the custom dig server and label from the endpoint host', () => {
  const resolver = normalizeCustomResolver({
    id: 'custom-no-dig',
    name: 'No dig address',
    endpoint: 'https://doh.example.net/resolve',
  });
  assert.equal(resolver.digServer, 'doh.example.net');
  assert.equal(resolver.address, 'doh.example.net');
});

test('rejects non-HTTPS, credential-bearing or shell-hostile custom resolvers', () => {
  const base = { id: 'custom-test', name: 'Test', endpoint: 'https://dns.example/dns-query' };
  assert.throws(() => normalizeCustomResolver({ ...base, endpoint: 'http://dns.example/dns-query' }), /HTTPS/);
  assert.throws(() => normalizeCustomResolver({ ...base, endpoint: 'https://user:pass@dns.example/dns-query' }), /credentials/);
  assert.throws(() => normalizeCustomResolver({ ...base, endpoint: 'javascript:alert(1)' }), /HTTPS/);
  assert.throws(() => normalizeCustomResolver({ ...base, digServer: '1.1.1.1; touch /tmp/pwn' }), /plain hostname/);
  assert.throws(() => normalizeCustomResolver({ ...base, id: 'cloudflare' }), /id is invalid/);
});

test('sanitizes stored custom resolvers and drops invalid or built-in ids', () => {
  const list = sanitizeCustomResolvers([
    { id: 'custom-ok', name: 'Ok', endpoint: 'https://dns.example/dns-query' },
    { id: 'custom-bad', name: 'Bad', endpoint: 'http://dns.example/dns-query' },
    { id: 'cloudflare', name: 'Spoof', endpoint: 'https://dns.example/dns-query' },
    { id: 'custom-ok', name: 'Duplicate', endpoint: 'https://dns.example/dns-query' },
    null,
  ]);
  assert.equal(list.length, 1);
  assert.equal(list[0].id, 'custom-ok');
  assert.equal(list[0].digServer, 'dns.example');
});

test('generates a safe id for new custom resolvers', () => {
  assert.match(customResolverId('Home DNS'), /^custom-home-dns-[a-z0-9]+$/);
});

test('queries a custom resolver endpoint and normalises the JSON answer', async () => {
  const resolver = normalizeCustomResolver({
    id: 'custom-mock',
    name: 'Mock resolver',
    endpoint: 'https://dns.example/dns-query?profile=test',
    address: '192.0.2.53',
  });
  const originalFetch = globalThis.fetch;
  let requested = '';
  globalThis.fetch = async (url) => {
    requested = String(url);
    return {
      ok: true,
      json: async () => ({
        Status: 0,
        AA: false,
        AD: true,
        Answer: [{ name: 'example.com.', type: 1, TTL: 60, data: '192.0.2.1' }],
      }),
    };
  };
  try {
    const result = await queryDns({ resolver, name: 'example.com', type: 'A' });
    assert.equal(result.ok, true);
    assert.equal(result.resolver.name, 'Mock resolver');
    assert.equal(result.rcode, 'NOERROR');
    assert.equal(result.flags.ad, true);
    assert.equal(result.answers[0].data, '192.0.2.1');
    const url = new URL(requested);
    assert.equal(url.origin, 'https://dns.example');
    assert.equal(url.searchParams.get('profile'), 'test');
    assert.equal(url.searchParams.get('type'), 'A');
  } finally {
    globalThis.fetch = originalFetch;
  }
});
