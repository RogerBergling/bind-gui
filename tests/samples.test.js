import test from 'node:test';
import assert from 'node:assert/strict';
import { SAMPLES } from '../public/assets/js/data/samples.js';
import { createWorkspace, parseWorkspace } from '../public/assets/js/dns/workspace.js';
import { analyzeWorkspace } from '../public/assets/js/dns/analyzer.js';

test('all samples parse into a usable workspace', async () => {
  for (const sample of SAMPLES) {
    const workspace = createWorkspace(sample.title, sample.files, { source: `sample:${sample.id}` });
    const model = parseWorkspace(workspace);
    assert.ok(model.zones.length > 0, `${sample.id} should have zones`);
    assert.ok(model.summary.records > 0, `${sample.id} should have records`);
    const analysis = await analyzeWorkspace(workspace, model);
    if (sample.id !== 'complete-authoritative') {
      assert.ok(analysis.findings.length > 0, `${sample.id} should produce findings`);
    }
  }
});

test('the problem clinic intentionally contains serious errors', async () => {
  const sample = SAMPLES.find((item) => item.id === 'problem-clinic');
  const workspace = createWorkspace(sample.title, sample.files);
  const model = parseWorkspace(workspace);
  const analysis = await analyzeWorkspace(workspace, model);
  assert.ok(analysis.counts.error >= 5);
  assert.ok(analysis.findings.some((finding) => finding.id === 'open-recursion'));
  assert.ok(analysis.findings.some((finding) => finding.id.startsWith('cname-apex')));
  assert.ok(analysis.findings.some((finding) => finding.id.startsWith('glue-missing')));
  assert.ok(analysis.findings.some((finding) => finding.id.startsWith('allow-update-any')));
});

test('the authoritative example has no syntax errors', () => {
  const sample = SAMPLES.find((item) => item.id === 'authoritative-example');
  const workspace = createWorkspace(sample.title, sample.files);
  const model = parseWorkspace(workspace);
  assert.equal(model.parseErrors.length, 0);
  assert.equal(model.zoneErrors.length, 0);
  assert.equal(model.zones.length, 3);
  assert.ok(model.zones.every((zone) => zone.parsed));
});

test('the complete authoritative example is structurally clean and scores 100', async () => {
  const sample = SAMPLES.find((item) => item.id === 'complete-authoritative');
  const workspace = createWorkspace(sample.title, sample.files);
  const model = parseWorkspace(workspace);
  assert.equal(model.parseErrors.length, 0);
  assert.equal(model.errors.length, 0);
  assert.equal(model.zoneErrors.length, 0);
  assert.equal(model.zones.length, 4);
  assert.equal(model.keys.length, 2);
  assert.equal(model.policies.length, 1);
  const analysis = await analyzeWorkspace(workspace, model);
  assert.equal(analysis.counts.error, 0);
  assert.equal(analysis.counts.warning, 0);
  assert.equal(analysis.score, 100, JSON.stringify(analysis.findings.map((finding) => finding.id)));
});
