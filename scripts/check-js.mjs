#!/usr/bin/env node
/* Syntax-check every browser and test ES module without a bundler. */

import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const directories = [join(root, 'public', 'assets', 'js'), join(root, 'tests')];
const files = [];

function walk(directory) {
  for (const entry of readdirSync(directory)) {
    const path = join(directory, entry);
    if (statSync(path).isDirectory()) walk(path);
    else if (path.endsWith('.js')) files.push(path);
  }
}

for (const directory of directories) {
  try {
    walk(directory);
  } catch {
    /* optional directory */
  }
}

const failures = [];
for (const file of files.sort()) {
  try {
    execFileSync(process.execPath, ['--check', file], { stdio: 'pipe' });
  } catch (error) {
    failures.push({ file, message: String(error.stderr || error.message) });
  }
  const source = readFileSync(file, 'utf8');
  if (/\beval\s*\(/.test(source) || /\bnew\s+Function\s*\(/.test(source)) {
    failures.push({ file, message: 'Uses eval() or new Function(); the CSP forbids it and it is not needed.' });
  }
}

if (failures.length) {
  console.error(`JavaScript check failed for ${failures.length} file(s):`);
  for (const failure of failures) {
    console.error(`  ${relative(root, failure.file)}: ${failure.message.trim()}`);
  }
  process.exit(1);
}

console.log(`Checked ${files.length} JavaScript module(s): syntax and CSP safety OK.`);
