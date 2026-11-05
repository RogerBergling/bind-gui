import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildDigCommands,
  buildDohUrl,
  compareDnsResults,
  normalizeAnswerValue,
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
  assert.ok(commands.some((item) => item.command.includes('-x 192.0.2.80')));
});
