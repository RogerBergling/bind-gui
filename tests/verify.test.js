import test from 'node:test';
import assert from 'node:assert/strict';
import { buildVerificationChecks, observedValues, summarizeVerification } from '../public/assets/js/dns/verify.js';
import { parseZone } from '../public/assets/js/dns/zone-parser.js';

const zone = {
  name: 'example.com.',
  parsed: parseZone(`$ORIGIN example.com.\n$TTL 60\n@ IN SOA ns1 hostmaster ( 1 3600 900 1209600 300 )\n@ IN NS ns1\nwww IN A 192.0.2.10\nwww IN A 192.0.2.11\nmail IN A 192.0.2.20\n@ IN MX 10 mail\n`, { origin: 'example.com.' }),
};

test('builds grouped verification checks from zone records', () => {
  const checks = buildVerificationChecks([zone], { limit: 10 });
  const www = checks.find((check) => check.owner === 'www.example.com.' && check.type === 'A');
  assert.ok(www);
  assert.equal(www.expected.size, 2);
  assert.ok(www.expected.has('192.0.2.10'));
  assert.ok(checks.length <= 10);
  assert.ok(checks.some((check) => check.owner === 'example.com.' && check.type === 'NS'));
});

test('compares observed answer values without TTL semantics', () => {
  const checks = buildVerificationChecks([zone], { limit: 10 });
  const www = checks.find((check) => check.owner === 'www.example.com.' && check.type === 'A');
  const observed = observedValues({ answers: [{ type: 'A', data: '192.0.2.10' }, { type: 'A', data: '192.0.2.11' }, { type: 'A', data: '192.0.2.12' }] }, www);
  assert.equal(observed.size, 3);
  assert.ok(observed.has('192.0.2.12'));
});

test('summarises verification results', () => {
  const summary = summarizeVerification([
    { status: 'match', ad: true },
    { status: 'mismatch', ad: false },
    { status: 'error', ad: false },
  ]);
  assert.equal(summary.total, 3);
  assert.equal(summary.match, 1);
  assert.equal(summary.mismatch, 1);
  assert.equal(summary.error, 1);
  assert.equal(summary.authenticated, 1);
});
