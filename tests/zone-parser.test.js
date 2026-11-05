import test from 'node:test';
import assert from 'node:assert/strict';
import { parseZone } from '../public/assets/js/dns/zone-parser.js';

const ZONE = `$ORIGIN example.com.
$TTL 3600

@ IN SOA ns1.example.com. hostmaster.example.com. (
  2026110501 3600 900 1209600 300 )

@ IN NS ns1.example.com.
@ IN NS ns2.example.net.
ns1 IN A 192.0.2.53
www IN A 192.0.2.80
www IN AAAA 2001:db8::80
mail IN A 192.0.2.25
@ IN MX 10 mail.example.com.
@ IN TXT "v=spf1 mx -all"
_sip._tcp IN SRV 10 60 5060 sip.example.com.
sip IN A 192.0.2.90
@ IN CAA 0 issue "letsencrypt.org"
`;

test('parses a normal zone with relative names and omitted owners', () => {
  const zone = parseZone(ZONE, { origin: 'example.com.', file: 'db.example.com' });
  assert.equal(zone.errors.length, 0);
  assert.equal(zone.soa.owner, 'example.com.');
  assert.equal(zone.soa.data.serial, 2026110501);
  assert.equal(zone.apexNS.length, 2);
  const www = zone.records.filter((record) => record.owner === 'www.example.com.');
  assert.equal(www.length, 2);
  assert.ok(www.some((record) => record.type === 'AAAA' && record.data.address === '2001:db8::80'));
  const mx = zone.records.find((record) => record.type === 'MX');
  assert.equal(mx.data.exchange, 'mail.example.com.');
  assert.equal(mx.data.preference, 10);
  const txt = zone.records.find((record) => record.type === 'TXT');
  assert.deepEqual(txt.data.strings, ['v=spf1 mx -all']);
  const srv = zone.records.find((record) => record.type === 'SRV');
  assert.equal(srv.owner, '_sip._tcp.example.com.');
  assert.equal(srv.data.port, 5060);
});

test('supports $ORIGIN, $TTL, $GENERATE and $INCLUDE', () => {
  const include = `$ORIGIN included.example.com.\n$TTL 120\nhost IN A 192.0.2.7\n`;
  const text = `$ORIGIN example.com.\n$TTL 300\n@ IN SOA ns1 hostmaster ( 1 3600 900 1209600 300 )\n$GENERATE 1-3 node-$ A 192.0.2.$\n$INCLUDE included.zone\n`;
  const zone = parseZone(text, {
    origin: 'example.com.',
    file: 'db.example.com',
    resolveInclude: (path) => (path === 'included.zone' ? { path: 'included.zone', content: include } : null),
  });
  assert.equal(zone.errors.length, 0);
  const generated = zone.records.filter((record) => record.generated);
  assert.equal(generated.length, 3);
  assert.deepEqual(generated.map((record) => record.owner), ['node-1.example.com.', 'node-2.example.com.', 'node-3.example.com.']);
  assert.ok(zone.records.some((record) => record.owner === 'host.included.example.com.'));
  assert.ok(zone.includedFiles.includes('included.zone'));
});

test('flags out-of-zone data, bad TTLs and unknown types', () => {
  const zone = parseZone(`$ORIGIN example.com.\n@ IN SOA ns1 hostmaster ( 1 3600 900 1209600 300 )\noutside.example. IN A 192.0.2.1\nbad IN A not-an-ip\nbad2 IN 3600 IN UNKNOWNTYPE x\n`, { origin: 'example.com.' });
  const outside = zone.records.find((record) => record.owner === 'outside.example.');
  assert.equal(outside.inZone, false);
  assert.ok(zone.errors.some((error) => error.message.includes('not a valid IPv4')));
  assert.ok(zone.errors.some((error) => error.message.includes('Unknown record type')));
});

test('parses DNSSEC records and canonicalises signatures', () => {
  const zone = parseZone(`$ORIGIN example.com.\n@ IN SOA ns1 hostmaster ( 1 3600 900 1209600 300 )\n@ IN DNSKEY 257 3 13 c2FtcGxlLWtleQ==\n@ IN DS 12345 13 2 ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789\n@ IN RRSIG SOA 13 2 3600 20261231000000 20261101000000 12345 example.com. c2ln\n`, { origin: 'example.com.' });
  assert.equal(zone.errors.length, 0);
  const dnskey = zone.records.find((record) => record.type === 'DNSKEY');
  assert.equal(dnskey.data.flags, 257);
  assert.equal(dnskey.data.algorithm, 13);
  const ds = zone.records.find((record) => record.type === 'DS');
  assert.equal(ds.data.keyTag, 12345);
  const rrsig = zone.records.find((record) => record.type === 'RRSIG');
  assert.equal(rrsig.data.covered, 'SOA');
  assert.equal(rrsig.data.signer, 'example.com.');
});

test('parses comments, parentheses and quoted semicolons', () => {
  const zone = parseZone(`$ORIGIN example.com.\n$TTL 60\n@ IN SOA ns1 hostmaster ( ; comment\n 1 3600 900 1209600 300 )\n@ IN TXT "semi;colon" ; trailing comment\n`, { origin: 'example.com.' });
  assert.equal(zone.errors.length, 0);
  const txt = zone.records.find((record) => record.type === 'TXT');
  assert.deepEqual(txt.data.strings, ['semi;colon']);
});
