import test from 'node:test';
import assert from 'node:assert/strict';
import { createWorkspace, inferZoneOrigin, parseWorkspace, zoneByName } from '../public/assets/js/dns/workspace.js';

const FILES = [
  {
    path: 'named.conf',
    content: `include "/etc/bind/named.conf.options";\ninclude "/etc/bind/named.conf.local";\n`,
  },
  {
    path: 'named.conf.options',
    content: `options {\n  directory "/var/cache/bind";\n  recursion no;\n  allow-transfer { none; };\n  version none;\n};\n`,
  },
  {
    path: 'named.conf.local',
    content: `key "xfr-key" { algorithm hmac-sha256; secret "c2FtcGxl"; };\nacl "secondaries" { 192.0.2.54; key "xfr-key"; };\nview "internal" {\n  match-clients { 10.0.0.0/8; };\n  recursion yes;\n  allow-recursion { 10.0.0.0/8; };\n  zone "example.com" {\n    type primary;\n    file "/etc/bind/zones/db.example.com";\n    allow-transfer { "secondaries"; };\n  };\n};\n`,
  },
  {
    path: 'zones/db.example.com',
    content: `$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1.example.com. hostmaster.example.com. ( 2026110501 3600 900 1209600 300 )\n@ IN NS ns1.example.com.\nns1 IN A 192.0.2.53\nwww IN A 192.0.2.80\n`,
  },
];

test('resolves absolute includes and zone files inside the workspace', () => {
  const workspace = createWorkspace('test', FILES);
  const model = parseWorkspace(workspace);
  assert.equal(model.entryFile, 'named.conf');
  assert.equal(model.includes.length, 2);
  assert.ok(model.includes.every((item) => item.resolved));
  assert.equal(model.zones.length, 1);
  const zone = model.zones[0];
  assert.equal(zone.name, 'example.com.');
  assert.equal(zone.view, 'internal');
  assert.equal(zone.filePath, 'zones/db.example.com');
  assert.equal(zone.parsed.records.length, 4);
  assert.equal(model.keys.length, 1);
  assert.equal(model.keys[0].algorithm, 'hmac-sha256');
  assert.equal(model.acls.length, 1);
  assert.equal(model.views.length, 1);
  assert.equal(model.options.get('recursion')[0].args[0], 'no');
  assert.equal(zoneByName(model, 'example.com').name, 'example.com.');
  assert.ok(model.summary.records >= 4);
});

test('reports missing includes and missing zone files', () => {
  const workspace = createWorkspace('broken', [
    { path: 'named.conf', content: `include "missing.conf";\nzone "example.com" { type primary; file "missing.zone"; };\n` },
  ]);
  const model = parseWorkspace(workspace);
  assert.equal(model.includes.length, 1);
  assert.equal(model.includes[0].resolved, false);
  assert.ok(model.errors.some((error) => error.message.includes('missing.conf')));
  assert.equal(model.zones.length, 1);
  assert.equal(model.zones[0].parsed, null);
  assert.ok(model.errors.some((error) => error.message.includes('missing.zone')));
});

test('parses a standalone zone file and infers its origin', () => {
  const content = `$TTL 3600\n@ IN SOA ns1.example.org. hostmaster.example.org. ( 1 3600 900 1209600 300 )\n@ IN NS ns1.example.org.\nwww IN A 192.0.2.10\n`;
  assert.equal(inferZoneOrigin('zones/example.org.zone', content), 'example.org.');
  const workspace = createWorkspace('zone-only', [{ path: 'zones/example.org.zone', content }]);
  const model = parseWorkspace(workspace);
  assert.equal(model.zones.length, 1);
  assert.equal(model.zones[0].synthetic, true);
  assert.equal(model.zones[0].name, 'example.org.');
  assert.equal(model.zones[0].parsed.records.length, 3);
});

test('handles duplicate includes and include cycles without hanging', () => {
  const workspace = createWorkspace('cycle', [
    { path: 'named.conf', content: `include "a.conf";\ninclude "a.conf";\n` },
    { path: 'a.conf', content: `include "named.conf";\n` },
  ]);
  const model = parseWorkspace(workspace);
  assert.ok(model.errors.some((error) => error.message.toLowerCase().includes('cycle')));
  assert.ok(model.warnings.some((warning) => warning.message.includes('more than once')));
});

test('creates synthetic zones from named zone declarations with view context', () => {
  const workspace = createWorkspace('views', [
    { path: 'named.conf', content: `view "a" { match-clients { any; }; recursion no; zone "a.example" { type primary; file "db.a"; }; };\nview "b" { match-clients { 10.0.0.0/8; }; recursion yes; zone "b.example" { type primary; file "db.b"; }; };\n` },
    { path: 'db.a', content: `$ORIGIN a.example.\n$TTL 60\n@ IN SOA ns1.a.example. hostmaster.a.example. ( 1 3600 900 1209600 300 )\n@ IN NS ns1.a.example.\n` },
    { path: 'db.b', content: `$ORIGIN b.example.\n$TTL 60\n@ IN SOA ns1.b.example. hostmaster.b.example. ( 1 3600 900 1209600 300 )\n@ IN NS ns1.b.example.\n` },
  ]);
  const model = parseWorkspace(workspace);
  assert.equal(model.zones.length, 2);
  assert.deepEqual(model.zones.map((zone) => zone.view).sort(), ['a', 'b']);
  assert.equal(model.views.length, 2);
});

test('keeps view context when an include is inside a view', () => {
  const workspace = createWorkspace('view-include', [
    { path: 'named.conf', content: `view "internal" { match-clients { 10.0.0.0/8; }; include "view-zones.conf"; };\n` },
    { path: 'view-zones.conf', content: `zone "inside.example" { type primary; file "db.inside"; };\n` },
    { path: 'db.inside', content: `$ORIGIN inside.example.\n$TTL 60\n@ IN SOA ns1.inside.example. hostmaster.inside.example. ( 1 3600 900 1209600 300 )\n@ IN NS ns1.inside.example.\n` },
  ]);
  const model = parseWorkspace(workspace);
  assert.equal(model.zones.length, 1);
  assert.equal(model.zones[0].view, 'internal');
  assert.equal(model.includes[0].resolved, true);
});
