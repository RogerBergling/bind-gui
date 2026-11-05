import test from 'node:test';
import assert from 'node:assert/strict';
import { createZip, crc32, readZip } from '../public/assets/js/dns/zip.js';

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
