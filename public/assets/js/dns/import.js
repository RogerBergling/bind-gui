/* Import helpers for files, folders, ZIP bundles and workspace JSON. */

import { isProbablyText, readFileBuffer, readFileText, safeJsonParse } from '../utils.js';
import { createWorkspace, detectFileKind, guessEntryFile, makeWorkspaceFile, normalizeWorkspacePath } from './workspace.js';
import { readZip } from './zip.js';

const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_FILES = 1500;
const GENERATED_FILES = new Set([
  'BIND-WORKBENCH-MANIFEST.json',
  'validate.sh',
  'VALIDATE.md',
  'VERIFY.md',
  'bind-workbench-workspace.json',
]);

function uniquePath(path, used) {
  const base = normalizeWorkspacePath(path, 'file');
  if (!used.has(base)) {
    used.add(base);
    return base;
  }
  const dot = base.lastIndexOf('.');
  const stem = dot > 0 ? base.slice(0, dot) : base;
  const extension = dot > 0 ? base.slice(dot) : '';
  let counter = 2;
  while (used.has(`${stem}-${counter}${extension}`)) counter += 1;
  const next = `${stem}-${counter}${extension}`;
  used.add(next);
  return next;
}

function workspaceNameFromFiles(files, fallback = 'Imported BIND workspace') {
  if (!files.length) return fallback;
  const firstPath = files[0].path || '';
  const parts = firstPath.split('/');
  if (parts.length > 2 && parts[0] && !parts[0].startsWith('.')) return parts[0];
  const directory = firstPath.includes('/') ? firstPath.split('/')[0] : '';
  return directory || fallback;
}

function parseWorkspaceJson(text) {
  const data = safeJsonParse(text, null);
  if (!data) return null;
  const workspace = data.workspace || (Array.isArray(data.files) ? data : null);
  if (!workspace || !Array.isArray(workspace.files)) return null;
  const files = workspace.files
    .filter((file) => file && typeof file.path === 'string' && typeof file.content === 'string')
    .map((file) => makeWorkspaceFile(file.path, file.content, file));
  if (!files.length) return null;
  return createWorkspace(workspace.name || 'Restored BIND workspace', files, {
    entry: workspace.entry || guessEntryFile(files),
    source: 'workspace-json',
    id: workspace.id,
    createdAt: workspace.createdAt,
    updatedAt: workspace.updatedAt,
  });
}

export async function workspaceFromFileList(fileList, options = {}) {
  const list = Array.from(fileList || []).filter(Boolean);
  const warnings = [];
  const used = new Set();
  const collected = [];
  let restored = null;

  for (const file of list) {
    if (collected.length >= MAX_FILES) {
      warnings.push(`Stopped after ${MAX_FILES} files.`);
      break;
    }
    if (file.size > MAX_FILE_BYTES) {
      warnings.push(`Skipped ${file.name}: larger than ${Math.round(MAX_FILE_BYTES / 1024 / 1024)} MiB.`);
      continue;
    }
    const path = file.webkitRelativePath || file.name || 'file';
    const lower = path.toLowerCase();
    if (lower.endsWith('.zip')) {
      try {
        const buffer = await readFileBuffer(file);
        const archive = await readZip(buffer);
        for (const entry of archive.files) {
          if (GENERATED_FILES.has(entry.path)) {
            if (entry.path === 'bind-workbench-workspace.json' && !restored) {
              restored = parseWorkspaceJson(entry.content);
            }
            continue;
          }
          collected.push({ path: uniquePath(entry.path, used), content: entry.content });
        }
        warnings.push(...archive.warnings);
      } catch (error) {
        warnings.push(`Could not read ZIP ${file.name}: ${error.message}`);
      }
      continue;
    }
    const text = await readFileText(file);
    if (!isProbablyText(text)) {
      warnings.push(`Skipped binary file ${file.name}.`);
      continue;
    }
    if (lower.endsWith('.json')) {
      const maybeWorkspace = parseWorkspaceJson(text);
      if (maybeWorkspace) {
        restored = maybeWorkspace;
        continue;
      }
    }
    if (GENERATED_FILES.has(path.split('/').pop())) continue;
    collected.push({ path: uniquePath(path, used), content: text });
  }

  if (restored && collected.length === 0) {
    return { workspace: restored, warnings };
  }
  if (restored && collected.length) {
    // Prefer the explicit workspace snapshot, but keep any extra files that
    // were imported alongside it.
    const existing = new Set(restored.files.map((file) => file.path));
    const extras = collected
      .filter((file) => !existing.has(file.path))
      .map((file) => makeWorkspaceFile(file.path, file.content));
    const workspace = createWorkspace(restored.name, [...restored.files, ...extras], {
      entry: restored.entry,
      source: 'workspace-json+files',
      id: restored.id,
    });
    return { workspace, warnings };
  }

  if (!collected.length) throw new Error('No readable text configuration files were found.');
  const files = collected.map((file) => makeWorkspaceFile(file.path, file.content));
  const name = options.name || workspaceNameFromFiles(files);
  const workspace = createWorkspace(name, files, { source: options.source || 'import' });
  return { workspace, warnings };
}

export async function workspaceFromClipboardText(text, options = {}) {
  if (!text || !text.trim()) throw new Error('The pasted text is empty.');
  const path = options.path || 'named.conf';
  const file = makeWorkspaceFile(path, text);
  const workspace = createWorkspace(options.name || 'Pasted BIND configuration', [file], { source: 'paste' });
  return { workspace, warnings: [] };
}

export function workspaceFromSample(sample) {
  const files = sample.files.map((file) => makeWorkspaceFile(file.path, file.content));
  return createWorkspace(sample.title, files, { source: `sample:${sample.id}` });
}

export function describeImport(file) {
  const path = file.webkitRelativePath || file.name || 'file';
  return { path, kind: detectFileKind(path, ''), size: file.size };
}

export function isLikelyConfigFile(file) {
  const name = (file.name || '').toLowerCase();
  return /\.(conf|cfg|zone|db|rev|hosts|signed|nzf|txt|json|zip|key|private|jnl)$/.test(name) || !name.includes('.');
}
