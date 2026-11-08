import test from 'node:test';
import assert from 'node:assert/strict';
import { deflateRawSync } from 'node:zlib';
import { createZip, crc32, readZip } from '../public/assets/js/dns/zip.js';

function zipWithLyingSize(name, expandedSize, declaredSize) {
  const nameBytes = new TextEncoder().encode(name);
  const payload = new Uint8Array(deflateRawSync(new Uint8Array(expandedSize)));
  const local = new Uint8Array(30 + nameBytes.length + payload.length);
  const localView = new DataView(local.buffer);
  localView.setUint32(0, 0x04034b50, true);
  localView.setUint16(4, 20, true);
  localView.setUint16(6, 0x0800, true);
  localView.setUint16(8, 8, true);
  localView.setUint32(18, payload.length, true);
  localView.setUint32(22, declaredSize, true);
  localView.setUint16(26, nameBytes.length, true);
  local.set(nameBytes, 30);
  local.set(payload, 30 + nameBytes.length);

  const central = new Uint8Array(46 + nameBytes.length);
  const centralView = new DataView(central.buffer);
  centralView.setUint32(0, 0x02014b50, true);
  centralView.setUint16(4, 20, true);
  centralView.setUint16(6, 20, true);
  centralView.setUint16(8, 0x0800, true);
  centralView.setUint16(10, 8, true);
  centralView.setUint32(20, payload.length, true);
  centralView.setUint32(24, declaredSize, true);
  centralView.setUint16(28, nameBytes.length, true);
  central.set(nameBytes, 46);

  const eocd = new Uint8Array(22);
  const eocdView = new DataView(eocd.buffer);
  eocdView.setUint32(0, 0x06054b50, true);
  eocdView.setUint16(8, 1, true);
  eocdView.setUint16(10, 1, true);
  eocdView.setUint32(12, central.length, true);
  eocdView.setUint32(16, local.length, true);

  const result = new Uint8Array(local.length + central.length + eocd.length);
  result.set(local, 0);
  result.set(central, local.length);
  result.set(eocd, local.length + central.length);
  return result;
}

test('creates and reads a ZIP archive', async () => {
  const zip = await createZip([
    { path: 'named.conf', content: 'options { recursion no; };\n' },
    { path: 'zones/db.example.com', content: '$ORIGIN example.com.\n@ IN SOA ns1 hostmaster ( 1 3600 900 1209600 300 )\n' },
  ]);
  assert.ok(zip.length > 100);
  const archive = await readZip(zip);
  assert.equal(archive.files.length, 2);
  assert.equal(archive.files[0].path, 'named.conf');
  assert.match(archive.files[0].content, /recursion no/);
  assert.match(archive.files[1].content, /SOA/);
  assert.equal(archive.warnings.length, 0);
});

test('creates a stored ZIP when compression is disabled', async () => {
  const zip = await createZip([{ path: 'a.txt', content: 'hello' }], { compress: false });
  const archive = await readZip(zip);
  assert.equal(archive.files.length, 1);
  assert.equal(archive.files[0].content, 'hello');
});

test('sanitises archive paths and deduplicates names', async () => {
  const zip = await createZip([
    { path: '../evil.conf', content: 'x' },
    { path: 'same.txt', content: 'one' },
    { path: 'same.txt', content: 'two' },
  ], { compress: false });
  const archive = await readZip(zip);
  assert.ok(archive.files.every((file) => !file.path.includes('..')));
  assert.equal(archive.files.filter((file) => file.path.startsWith('same')).length, 2);
});

test('CRC32 matches a known value', () => {
  assert.equal(crc32(new TextEncoder().encode('123456789')), 0xcbf43926);
});

test('rejects a non-ZIP input', async () => {
  await assert.rejects(() => readZip(new Uint8Array([1, 2, 3, 4])), /not a readable ZIP/);
});

test('caps decompression even when the declared entry size lies', async () => {
  const bomb = zipWithLyingSize('bomb.txt', 2 * 1024 * 1024, 16);
  const archive = await readZip(bomb, {
    maxFileSize: 256 * 1024,
    maxTotalSize: 4 * 1024 * 1024,
    maxCompressionRatio: 50,
  });

  assert.equal(archive.files.length, 0);
  assert.ok(archive.warnings.some((warning) => /decompressed data exceeds/.test(warning)));
  assert.equal(archive.warnings.some((warning) => /size mismatch/.test(warning)), false);
});
