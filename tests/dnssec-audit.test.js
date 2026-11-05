import test from 'node:test';
import assert from 'node:assert/strict';
import { base32Hex, canonicalRdataWire, nsec3Hash } from '../public/assets/js/dns/dnssec-audit.js';

test('NSEC3 base32hex encoding matches the RFC alphabet', () => {
  assert.equal(base32Hex(new Uint8Array([0, 0, 0, 0, 0])), '00000000');
  assert.equal(base32Hex(new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff])), 'VVVVVVVV');
});

test('NSEC3 hash matches an independent SHA-1/base32hex calculation', async () => {
  const first = await nsec3Hash('example.com.', '-', 0, 1);
  assert.equal(first.ok, true);
  assert.equal(first.base32, 'ONIB9MGUB9H0RML3CDF5BGRJ59DKJHVK');
  const second = await nsec3Hash('www.example.com.', 'AABB', 1, 1);
  assert.equal(second.ok, true);
  assert.equal(second.base32, 'HJRKPC2K6OJC5483VOVJRP9CI1BIMKPI');
});

test('canonical RDATA wire encoding covers common signed types', () => {
  assert.deepEqual(Array.from(canonicalRdataWire('A', '192.0.2.1')), [192, 0, 2, 1]);
  assert.deepEqual(Array.from(canonicalRdataWire('AAAA', '2001:db8::1')), [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
  assert.deepEqual(Array.from(canonicalRdataWire('NSEC3PARAM', '1 0 0 -')), [1, 0, 0, 0, 0]);
  assert.deepEqual(Array.from(canonicalRdataWire('MX', '10 mail.example.com.')), [0, 10, 4, 109, 97, 105, 108, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0]);
  assert.equal(canonicalRdataWire('TYPE65280', 'opaque'), null);
});
