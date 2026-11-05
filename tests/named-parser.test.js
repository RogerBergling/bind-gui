import test from 'node:test';
import assert from 'node:assert/strict';
import { parseNamed, findStatements, flattenStatements, statementToText } from '../public/assets/js/dns/named-parser.js';

test('parses nested named.conf statements and quoted strings', () => {
  const text = `// leading comment
options {
  directory "/var/cache/bind";
  recursion no;
  allow-transfer { none; };
};
zone "example.com" {
  type primary;
  file "db.example.com";
};
`;
  const parsed = parseNamed(text, { file: 'named.conf' });
  assert.equal(parsed.errors.length, 0);
  assert.equal(parsed.statements.length, 2);
  const options = parsed.statements[0];
  assert.equal(options.keyword, 'options');
  assert.equal(options.body.length, 3);
  assert.equal(options.body[0].keyword, 'directory');
  assert.equal(options.body[0].args[0], '/var/cache/bind');
  const zone = parsed.statements[1];
  assert.equal(zone.args[0], 'example.com');
  assert.equal(findStatements(parsed.statements, 'zone').length, 1);
});

test('handles hash and block comments and escaped quotes', () => {
  const text = `# hash comment
/* block
comment */
key "x" { secret "a\\"b"; };
`;
  const parsed = parseNamed(text, { file: 'named.conf' });
  assert.equal(parsed.errors.length, 0);
  assert.equal(parsed.statements[0].keyword, 'key');
  assert.equal(parsed.statements[0].body[0].args[0], 'a"b');
});

test('reports unclosed blocks and missing semicolons', () => {
  const parsed = parseNamed(`options { recursion no;`, { file: 'named.conf' });
  assert.ok(parsed.errors.some((error) => error.message.includes('Unclosed block')));
});

test('flattens statements with context and round-trips to text', () => {
  const parsed = parseNamed(`options { recursion no; };`, { file: 'named.conf' });
  const flat = flattenStatements(parsed.statements);
  assert.equal(flat.length, 2);
  assert.deepEqual(flat[1].context, ['options']);
  const text = statementToText(parsed.statements[0]);
  assert.match(text, /options \{/);
  assert.match(text, /recursion no;/);
});
