import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';

import { buildExportFiles } from '../public/assets/js/dns/export.js';
import { buildDigCommands } from '../public/assets/js/dns/doh.js';
import { auditDigCommands } from '../public/assets/js/dns/dnssec-audit.js';
import { normalizeName } from '../public/assets/js/dns/names.js';
import { createWorkspace, parseWorkspace } from '../public/assets/js/dns/workspace.js';
import { shellQuote } from '../public/assets/js/utils.js';

const HOSTILE = "evil'; touch /tmp/pwn; #";
const QUOTED = "'evil'\\''; touch /tmp/pwn; #'";

function hostileWorkspace() {
  const workspace = createWorkspace('Hostile workspace', [
    {
      path: 'named.conf',
      content: `options { recursion no; };\nzone "${HOSTILE}" { type primary; file "db.evil"; };\n`,
    },
    {
      path: 'db.evil',
      content: `$ORIGIN ${HOSTILE}.\n$TTL 3600\n@ IN SOA ns1.${HOSTILE}. hostmaster.${HOSTILE}. ( 1 3600 900 1209600 300 )\n@ IN NS ns1.${HOSTILE}.\n`,
    },
  ]);
  return { workspace, model: parseWorkspace(workspace) };
}

test('shellQuote round-trips a hostile zone name through a real shell', () => {
  assert.equal(shellQuote(HOSTILE), QUOTED);
  const echoed = execFileSync('sh', ['-c', `printf '%s' ${QUOTED}`], { encoding: 'utf8' });
  assert.equal(echoed, HOSTILE);
});

test('exported validation and verification commands quote a hostile zone name', async () => {
  const { workspace, model } = hostileWorkspace();
  const bundle = await buildExportFiles(workspace, model, { includeValidation: true });
  const byPath = new Map(bundle.files.map((file) => [file.path, file.content]));

  const quotedZone = shellQuote(model.zones[0].name);
  const manifest = JSON.parse(byPath.get('BIND-WORKBENCH-MANIFEST.json'));
  assert.ok(manifest.validation.commands.length > 0);
  for (const command of manifest.validation.commands) {
    assert.ok(command.includes(quotedZone), `command must quote the hostile zone name: ${command}`);
    assert.equal(command.includes(`named-checkzone ${model.zones[0].name}`), false);
  }

  for (const name of ['validate.sh', 'VERIFY.md']) {
    const content = byPath.get(name);
    assert.ok(content.includes(quotedZone), `${name} must quote the hostile zone name`);
    assert.equal(content.includes(`named-checkzone ${model.zones[0].name}`), false, `${name} must not contain an unquoted zone name`);
  }

  const commands = buildDigCommands({ name: HOSTILE, type: 'A', resolver: 'cloudflare', dnssec: true });
  const quotedName = shellQuote(normalizeName(HOSTILE));
  for (const item of commands) {
    if (item.command.includes('ns1.example.com')) continue;
    assert.ok(item.command.includes(quotedName), `dig command must quote the query name: ${item.command}`);
  }
});

test('DNSSEC audit commands quote a hostile apex', () => {
  const apex = normalizeName(HOSTILE);
  const quotedApex = shellQuote(apex);
  const quotedRandom = shellQuote(`random.${apex}`);
  const commands = auditDigCommands({ apex, denial: null });
  for (const command of commands) {
    assert.ok(
      command.includes(quotedApex) || command.includes(quotedRandom),
      `audit command must quote the apex: ${command}`,
    );
  }
});
