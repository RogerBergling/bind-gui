import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeWorkspace } from '../public/assets/js/dns/analyzer.js';
import { createWorkspace, parseWorkspace } from '../public/assets/js/dns/workspace.js';

function validFiles() {
  return [
    {
      path: 'named.conf',
      content: `options {\n  directory "/var/cache/bind";\n  listen-on port 53 { 127.0.0.1; 192.0.2.53; };\n  recursion no;\n  allow-transfer { none; };\n  dnssec-validation auto;\n  version none;\n  minimal-responses yes;\n};\nzone "example.com" { type primary; file "zones/db.example.com"; };\n`,
    },
    {
      path: 'zones/db.example.com',
      content: `$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1.example.com. hostmaster.example.com. ( 2026110501 3600 900 1209600 300 )\n@ IN NS ns1.example.com.\nns1 IN A 192.0.2.53\nwww IN A 192.0.2.80\n@ IN MX 10 mail.example.com.\nmail IN A 192.0.2.25\n@ IN CAA 0 issue "letsencrypt.org"\n`,
    },
  ];
}

async function analyze(files) {
  const workspace = createWorkspace('test', files);
  const model = parseWorkspace(workspace);
  return { workspace, model, analysis: await analyzeWorkspace(workspace, model) };
}

test('a clean authoritative configuration has no errors', async () => {
  const { analysis } = await analyze(validFiles());
  assert.equal(analysis.counts.error, 0);
  assert.ok(analysis.score >= 80);
  assert.equal(analysis.checklist.find((item) => item.id === 'check-recursion').status, 'pass');
  assert.ok(analysis.checklist.length >= 15);
});

test('detects open recursion and open transfers', async () => {
  const files = validFiles();
  files[0].content = `options {\n  recursion yes;\n  allow-recursion { any; };\n  allow-query-cache { any; };\n  allow-transfer { any; };\n};\nzone "example.com" { type primary; file "zones/db.example.com"; };\n`;
  const { analysis } = await analyze(files);
  assert.ok(analysis.findings.some((finding) => finding.id === 'open-recursion'));
  assert.ok(analysis.findings.some((finding) => finding.id.startsWith('open-cache')));
  assert.ok(analysis.findings.some((finding) => finding.id.startsWith('transfer-any')));
  assert.ok(analysis.counts.error >= 3);
});

test('detects CNAME at the apex and CNAME plus other data', async () => {
  const files = validFiles();
  files[1].content = `$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1.example.com. hostmaster.example.com. ( 1 3600 900 1209600 300 )\n@ IN NS ns1.example.com.\n@ IN CNAME target.example.net.\nwww IN A 192.0.2.80\nwww IN CNAME target.example.net.\n`;
  const { analysis } = await analyze(files);
  assert.ok(analysis.findings.some((finding) => finding.id.includes('cname-apex')));
  assert.ok(analysis.findings.some((finding) => finding.id.includes('cname-other-data')));
});

test('detects missing glue for an in-bailiwick delegation', async () => {
  const files = validFiles();
  files[1].content += `\nchild IN NS ns1.child.example.com.\n`;
  const { analysis } = await analyze(files);
  assert.ok(analysis.findings.some((finding) => finding.id.startsWith('glue-missing')));
});

test('detects a parent DS that does not match the imported child DNSKEY', async () => {
  const files = [
    {
      path: 'named.conf',
      content: `options { recursion no; allow-transfer { none; }; };\nzone "parent.example" { type primary; file "db.parent"; };\nzone "child.parent.example" { type primary; file "db.child"; };\n`,
    },
    {
      path: 'db.parent',
      content: `$ORIGIN parent.example.\n$TTL 3600\n@ IN SOA ns1.parent.example. hostmaster.parent.example. ( 1 3600 900 1209600 300 )\n@ IN NS ns1.parent.example.\nns1 IN A 192.0.2.53\nchild IN NS ns1.child.parent.example.\nns1.child IN A 192.0.2.80\nchild IN DS 12345 13 2 ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789\n`,
    },
    {
      path: 'db.child',
      content: `$ORIGIN child.parent.example.\n$TTL 3600\n@ IN SOA ns1.child.parent.example. hostmaster.child.parent.example. ( 1 3600 900 1209600 300 )\n@ IN NS ns1.child.parent.example.\n@ IN DNSKEY 257 3 13 c2FtcGxlLWtleQ==\n`,
    },
  ];
  const { analysis } = await analyze(files);
  assert.ok(analysis.findings.some((finding) => finding.id.startsWith('ds-mismatch')), JSON.stringify(analysis.findings.map((finding) => finding.id)));
});

test('detects missing SOA, missing NS and weak TSIG algorithms', async () => {
  const files = [
    { path: 'named.conf', content: `key "legacy" { algorithm hmac-md5; secret "c2hvcnQ="; };\nzone "bad.example" { type primary; file "db.bad"; };\n` },
    { path: 'db.bad', content: `$ORIGIN bad.example.\n$TTL 60\nwww IN A 192.0.2.10\n` },
  ];
  const { analysis } = await analyze(files);
  assert.ok(analysis.findings.some((finding) => finding.id.startsWith('zone-no-soa')));
  assert.ok(analysis.findings.some((finding) => finding.id.startsWith('zone-no-ns')));
  assert.ok(analysis.findings.some((finding) => finding.id.startsWith('tsig-md5')));
});

test('marks expired RRSIG records and modern DNSSEC recommendations', async () => {
  const files = validFiles();
  files[1].content += `\n@ IN DNSKEY 256 3 5 c2FtcGxlLWtleQ==\n@ IN RRSIG A 5 2 3600 20200101000000 20190101000000 12345 example.com. c2ln\n`;
  const { analysis } = await analyze(files);
  assert.ok(analysis.findings.some((finding) => finding.id.startsWith('rrsig')));
  assert.ok(analysis.findings.some((finding) => finding.id.startsWith('dnskey-weak-alg')));
});

test('expands named ACLs when checking open recursion', async () => {
  const files = validFiles();
  files[0].content = `acl "everyone" { any; };\noptions { recursion yes; allow-recursion { everyone; }; allow-transfer { none; }; };\nzone "example.com" { type primary; file "zones/db.example.com"; };\n`;
  const { analysis } = await analyze(files);
  assert.ok(analysis.findings.some((finding) => finding.id === 'open-recursion'));
});

test('does not warn about allow-update none', async () => {
  const files = validFiles();
  files[0].content = `options { recursion no; allow-transfer { none; }; };\nzone "example.com" { type primary; file "zones/db.example.com"; allow-update { none; }; };\n`;
  const { analysis } = await analyze(files);
  assert.equal(analysis.findings.filter((finding) => finding.id.startsWith('allow-update')).length, 0);
});
