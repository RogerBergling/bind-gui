import test from 'node:test';
import assert from 'node:assert/strict';
import { diffStats, lineDiff, semanticNamedDiff, semanticZoneDiff } from '../public/assets/js/dns/diff.js';
import { parseNamed } from '../public/assets/js/dns/named-parser.js';
import { parseZone } from '../public/assets/js/dns/zone-parser.js';

test('line diff finds additions, deletions and context', () => {
  const operations = lineDiff('a\nb\nc\n', 'a\nx\nc\n');
  const stats = diffStats(operations);
  assert.equal(stats.added, 1);
  assert.equal(stats.deleted, 1);
  assert.equal(stats.hunks, 1);
  assert.equal(stats.identical, false);
  assert.equal(stats.same, 2);
  assert.deepEqual(operations.map((operation) => operation.type), ['same', 'del', 'add', 'same']);
});

test('line diff handles empty and identical inputs', () => {
  assert.equal(lineDiff('', '').length, 0);
  assert.ok(diffStats(lineDiff('same\n', 'same\n')).identical);
  const added = lineDiff('', 'one\ntwo\n');
  assert.equal(added.filter((operation) => operation.type === 'add').length, 2);
});

test('semantic zone diff ignores order but catches records, TTLs and serials', () => {
  const a = parseZone(`$ORIGIN example.com.\n$TTL 60\n@ IN SOA ns1 hostmaster ( 1 3600 900 1209600 300 )\n@ IN NS ns1\nwww IN A 192.0.2.10\n`, { origin: 'example.com.' });
  const b = parseZone(`$ORIGIN example.com.\n$TTL 60\n@ IN SOA ns1 hostmaster ( 2 3600 900 1209600 300 )\n@ IN NS ns1\nwww IN A 192.0.2.10\nnew IN A 192.0.2.20\n`, { origin: 'example.com.' });
  const diff = semanticZoneDiff(a, b);
  assert.equal(diff.added.length, 1);
  assert.equal(diff.removed.length, 0);
  assert.deepEqual(diff.serialChange, { before: 1, after: 2 });
  assert.equal(diff.identical, false);
});

test('semantic zone diff detects TTL changes', () => {
  const a = parseZone(`$ORIGIN example.com.\n$TTL 60\n@ IN SOA ns1 hostmaster ( 1 3600 900 1209600 300 )\n@ IN NS ns1\nwww 60 IN A 192.0.2.10\n`, { origin: 'example.com.' });
  const b = parseZone(`$ORIGIN example.com.\n$TTL 60\n@ IN SOA ns1 hostmaster ( 1 3600 900 1209600 300 )\n@ IN NS ns1\nwww 120 IN A 192.0.2.10\n`, { origin: 'example.com.' });
  const diff = semanticZoneDiff(a, b);
  assert.equal(diff.ttlChanged.length, 1);
});

test('semantic named diff catches directive changes', () => {
  const a = parseNamed(`options { recursion no; };`, { file: 'named.conf' });
  const b = parseNamed(`options { recursion yes; };`, { file: 'named.conf' });
  const diff = semanticNamedDiff({ named: { statements: a.statements } }, { named: { statements: b.statements } });
  assert.ok(diff.added.some((statement) => statement.keyword === 'recursion'));
  assert.ok(diff.removed.some((statement) => statement.keyword === 'recursion'));
});
