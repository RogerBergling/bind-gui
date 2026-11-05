import test from 'node:test';
import assert from 'node:assert/strict';
import { buildExportFiles, buildWorkspaceJson } from '../public/assets/js/dns/export.js';
import { createWorkspace, parseWorkspace } from '../public/assets/js/dns/workspace.js';

const workspace = createWorkspace('Example workspace', [
  {
    path: 'named.conf',
    content: `options { recursion no; allow-transfer { none; }; };\nzone "example.com" { type primary; file "db.example.com"; };\n`,
  },
  {
    path: 'db.example.com',
    content: `$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1.example.com. hostmaster.example.com. ( 2026110501 3600 900 1209600 300 )\n@ IN NS ns1.example.com.\nns1 IN A 192.0.2.53\n`,
  },
]);
const model = parseWorkspace(workspace);

test('builds a multi-file export bundle with a manifest and validation script', async () => {
  const bundle = await buildExportFiles(workspace, model, { includeWorkspaceJson: true, includeValidation: true });
  const paths = bundle.files.map((file) => file.path);
  assert.ok(paths.includes('named.conf'));
  assert.ok(paths.includes('db.example.com'));
  assert.ok(paths.includes('BIND-WORKBENCH-MANIFEST.json'));
  assert.ok(paths.includes('validate.sh'));
  assert.ok(paths.includes('VALIDATE.md'));
  assert.ok(paths.includes('VERIFY.md'));
  assert.ok(paths.includes('bind-workbench-workspace.json'));
  const manifest = JSON.parse(bundle.files.find((file) => file.path === 'BIND-WORKBENCH-MANIFEST.json').content);
  assert.equal(manifest.tool, 'BIND Workbench');
  assert.equal(manifest.zones.length, 1);
  assert.ok(manifest.files.some((file) => file.path === 'db.example.com'));
  assert.ok(bundle.filename.endsWith('.zip'));
});

test('validation script uses named-checkconf and named-checkzone', async () => {
  const bundle = await buildExportFiles(workspace, model, { includeValidation: true });
  const script = bundle.files.find((file) => file.path === 'validate.sh').content;
  assert.match(script, /named-checkconf -z/);
  assert.match(script, /named-checkzone/);
  assert.match(script, /example\.com\./);
});

test('workspace JSON includes a warning about secrets', () => {
  const json = JSON.parse(buildWorkspaceJson(workspace));
  assert.equal(json.format, 'bind-workbench-workspace');
  assert.match(json.warning, /secrets/i);
});
