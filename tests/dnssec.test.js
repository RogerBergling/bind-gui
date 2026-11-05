import test from 'node:test';
import assert from 'node:assert/strict';
import { bytesToBase64 } from '../public/assets/js/utils.js';
import {
  dnskeyTag,
  dsDigest,
  matchDsToDnskeys,
  parseDnskeyRdata,
  parseDsRdata,
  parseRrsigRdata,
  rrsigHealth,
  zoneDnssecInventory,
} from '../public/assets/js/dns/dnssec.js';
import { parseZone } from '../public/assets/js/dns/zone-parser.js';

const PUBLIC_KEY = bytesToBase64(new Uint8Array(32).fill(7));
const DNSKEY = `257 3 13 ${PUBLIC_KEY}`;

test('computes a stable DNSKEY key tag', () => {
  const parsed = parseDnskeyRdata(DNSKEY);
  assert.equal(parsed.flags, 257);
  assert.equal(parsed.algorithm, 13);
  const tag = dnskeyTag(parsed);
  assert.ok(Number.isInteger(tag) && tag >= 0 && tag <= 65535);
  assert.equal(dnskeyTag(parsed), tag);
});

test('recomputes a DS digest and matches the DNSKEY', async () => {
  const digest = await dsDigest('example.com.', DNSKEY, 2);
  assert.equal(digest.ok, true);
  assert.equal(digest.digest.length, 64);
  const tag = dnskeyTag(DNSKEY);
  const ds = parseDsRdata(`${tag} 13 2 ${digest.digest}`);
  const match = await matchDsToDnskeys('example.com.', [ds], [DNSKEY]);
  assert.equal(match.status, 'match');
  assert.equal(match.results[0].status, 'match');
});

test('detects a DS mismatch', async () => {
  const tag = dnskeyTag(DNSKEY);
  const ds = parseDsRdata(`${tag} 13 2 ${'AB'.repeat(32)}`);
  const match = await matchDsToDnskeys('example.com.', [ds], [DNSKEY]);
  assert.equal(match.status, 'bogus');
  assert.equal(match.results[0].status, 'mismatch');
});

test('parses RRSIG times and reports expiry health', () => {
  const parsed = parseRrsigRdata('SOA 13 2 3600 20200101000000 20190101000000 12345 example.com. c2ln');
  assert.equal(parsed.covered, 'SOA');
  assert.ok(parsed.expiration < Math.floor(Date.now() / 1000));
  const zone = parseZone(`$ORIGIN example.com.\n@ IN SOA ns1 hostmaster ( 1 3600 900 1209600 300 )\n@ IN RRSIG SOA 13 2 3600 20200101000000 20190101000000 12345 example.com. c2ln\n`, { origin: 'example.com.' });
  assert.equal(zone.errors.length, 0);
  const health = rrsigHealth(zone);
  assert.ok(health.some((finding) => finding.severity === 'error'));
  const inventory = zoneDnssecInventory(zone);
  assert.equal(inventory.signed, true);
  assert.equal(inventory.hasKeys, false);
});
