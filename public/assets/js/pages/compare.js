/* Compare two files, or the current workspace with a saved snapshot. */

import { changedFilePaths, lineDiff, semanticNamedDiff, semanticZoneDiff } from '../dns/diff.js';
import { detectFileKind, inferZoneOrigin } from '../dns/workspace.js';
import { parseNamed } from '../dns/named-parser.js';
import { parseZone } from '../dns/zone-parser.js';
import { getCurrentWorkspace, getHistory, getSnapshot } from '../storage.js';
import { icon, pill, renderDiff, toast, wireCopyButtons } from '../ui.js';
import { escapeHTML, formatDateTime, formatNumber, readFileText } from '../utils.js';

export async function renderCompare(view, query) {
  const workspace = getCurrentWorkspace();
  const history = getHistory();
  const mode = query.get('mode') === 'snapshot' ? 'snapshot' : 'files';
  const initialSnapshot = query.get('snapshot') || history[0]?.id || null;
  let leftText = '';
  let rightText = '';
  let leftPath = '';
  let rightPath = '';
  let comparison = null;
  let snapshotId = initialSnapshot;
  let snapshotFile = null;

  view.innerHTML = `<div class="page-head">
    <div class="page-head-copy"><span class="eyebrow">Compare</span><h1>See exactly what changed</h1><p class="page-lede">A line diff shows the text. The semantic view shows records added or removed, TTL changes, SOA serial changes and named.conf directive changes — even when lines moved.</p><div class="meta-strip">${pill('line diff', 'accent', 'diff')}${pill('semantic zone diff', 'neutral', 'database')}${pill('named.conf structure', 'neutral', 'file')}</div></div>
    <div class="page-actions"><a class="btn" href="#/workbench">${icon('code', 16)} Workbench</a><a class="btn" href="#/history">${icon('clock', 16)} History</a></div>
  </div>
  <div class="tabbar" role="tablist">
    <button class="tab" type="button" role="tab" data-compare-mode="files" aria-selected="${mode === 'files'}">${icon('file', 15)} Two files</button>
    <button class="tab" type="button" role="tab" data-compare-mode="snapshot" aria-selected="${mode === 'snapshot'}">${icon('clock', 15)} Snapshot vs current</button>
  </div>
  <section data-compare-panel="files" ${mode === 'files' ? '' : 'hidden'}>
    <div class="compare-grid">
      <article class="compare-side">
        <div class="compare-head"><h2>${icon('file', 16)} Left / old</h2><div><select class="select" id="left-workspace-file" aria-label="Load a workspace file"><option value="">Load workspace file…</option>${workspace?.files?.map((file) => `<option value="${escapeHTML(file.path)}">${escapeHTML(file.path)}</option>`).join('') || ''}</select><label class="btn btn-sm btn-ghost">${icon('upload', 14)} File<input type="file" id="left-file" hidden></label></div></div>
        <label class="field"><span>Path / label</span><input id="left-path" type="text" placeholder="named.conf or zones/db.example.com" value="${escapeHTML(leftPath)}"></label>
        <label class="field"><span>Content</span><textarea id="left-text" class="compare-editor" spellcheck="false" placeholder="Paste a named.conf or zone file here…"></textarea></label>
      </article>
      <article class="compare-side">
        <div class="compare-head"><h2>${icon('file', 16)} Right / new</h2><div><select class="select" id="right-workspace-file" aria-label="Load a workspace file"><option value="">Load workspace file…</option>${workspace?.files?.map((file) => `<option value="${escapeHTML(file.path)}">${escapeHTML(file.path)}</option>`).join('') || ''}</select><label class="btn btn-sm btn-ghost">${icon('upload', 14)} File<input type="file" id="right-file" hidden></label></div></div>
        <label class="field"><span>Path / label</span><input id="right-path" type="text" placeholder="named.conf or zones/db.example.com" value="${escapeHTML(rightPath)}"></label>
        <label class="field"><span>Content</span><textarea id="right-text" class="compare-editor" spellcheck="false" placeholder="Paste the other version here…"></textarea></label>
      </article>
    </div>
    <div class="compare-actions"><button class="btn btn-primary" type="button" id="run-compare">${icon('diff', 16)} Compare files</button><button class="btn btn-ghost" type="button" id="swap-compare">${icon('refresh', 15)} Swap</button><span class="muted-note">Nothing is uploaded. Large files are diffed in the browser.</span></div>
    <div id="compare-output" class="compare-output">${comparison ? renderComparison(comparison) : `<div class="empty-panel"><h2>No comparison yet</h2><p>Load two files or paste them, then compare. If both are zone files, the app also compares records semantically.</p></div>`}</div>
  </section>
  <section data-compare-panel="snapshot" ${mode === 'snapshot' ? '' : 'hidden'}>
    ${history.length && workspace ? `<div class="query-card">
      <div class="query-grid">
        <label class="field span-2"><span>Snapshot</span><select id="snapshot-id" class="select">${history.map((snapshot) => `<option value="${snapshot.id}" ${snapshot.id === snapshotId ? 'selected' : ''}>${escapeHTML(formatDateTime(snapshot.createdAt))} · ${escapeHTML(snapshot.name)} · ${snapshot.files} files · ${escapeHTML(snapshot.label || snapshot.source)}</option>`).join('')}</select><small>The comparison is against the current workspace. Snapshots are created on import, manual save, export or restore.</small></label>
      </div>
      <div class="query-actions"><button class="btn btn-primary" type="button" id="run-snapshot-compare">${icon('diff', 15)} Compare snapshot with current</button><a class="btn btn-ghost" href="#/history">${icon('clock', 15)} Manage history</a></div>
    </div>
    <div id="snapshot-output">${snapshotId ? `<div class="empty-panel"><h2>Ready to compare</h2><p>Click the button to list changed files and inspect their line and semantic diffs.</p></div>` : `<div class="empty-panel"><h2>No snapshots yet</h2><p>Import a workspace or press Save snapshot in the workbench. The current workspace is then available for comparison.</p><a class="btn btn-primary" href="#/workbench">Open workbench</a></div>`}</div>` : `<div class="empty-panel"><h2>No snapshot comparison available</h2><p>${workspace ? 'Save a snapshot from the workbench first.' : 'Import a workspace first; history lives in this browser.'}</p><a class="btn btn-primary" href="#/workbench">${icon('code', 15)} Open workbench</a><a class="btn" href="#/history">History</a></div>`}
  </section>
  <div class="callout info">${icon('info', 18)}<div><strong>Comparison is not validation</strong><p>Two identical files can still be wrong, and a small diff can be dangerous. Run Analyze and named-checkconf/named-checkzone after choosing the new version. The snapshot comparison is local browser history, not a Git history.</p></div></div>
  `;

  const leftInput = view.querySelector('#left-text');
  const rightInput = view.querySelector('#right-text');
  const leftPathInput = view.querySelector('#left-path');
  const rightPathInput = view.querySelector('#right-path');
  const output = view.querySelector('#compare-output');

  function fillFromWorkspace(path, side) {
    const file = workspace?.files.find((item) => item.path === path);
    if (!file) return;
    if (side === 'left') {
      leftText = file.content;
      leftPath = file.path;
      leftInput.value = leftText;
      leftPathInput.value = leftPath;
    } else {
      rightText = file.content;
      rightPath = file.path;
      rightInput.value = rightText;
      rightPathInput.value = rightPath;
    }
  }

  view.querySelectorAll('[data-compare-mode]').forEach((button) => {
    button.addEventListener('click', () => {
      const next = button.dataset.compareMode;
      view.querySelectorAll('[data-compare-mode]').forEach((item) => item.setAttribute('aria-selected', String(item === button)));
      view.querySelectorAll('[data-compare-panel]').forEach((panel) => {
        panel.hidden = panel.dataset.comparePanel !== next;
      });
    });
  });

  view.querySelector('#left-workspace-file')?.addEventListener('change', (event) => fillFromWorkspace(event.target.value, 'left'));
  view.querySelector('#right-workspace-file')?.addEventListener('change', (event) => fillFromWorkspace(event.target.value, 'right'));
  view.querySelector('#left-file')?.addEventListener('change', async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    leftText = await readFileText(file);
    leftPath = file.name;
    leftInput.value = leftText;
    leftPathInput.value = leftPath;
  });
  view.querySelector('#right-file')?.addEventListener('change', async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    rightText = await readFileText(file);
    rightPath = file.name;
    rightInput.value = rightText;
    rightPathInput.value = rightPath;
  });

  view.querySelector('#swap-compare')?.addEventListener('click', () => {
    const previousText = leftInput.value;
    const previousPath = leftPathInput.value;
    leftInput.value = rightInput.value;
    leftPathInput.value = rightPathInput.value;
    rightInput.value = previousText;
    rightPathInput.value = previousPath;
    toast('Swapped sides.', 'ok');
  });

  view.querySelector('#run-compare')?.addEventListener('click', async () => {
    leftText = leftInput.value;
    rightText = rightInput.value;
    leftPath = leftPathInput.value.trim() || 'left';
    rightPath = rightPathInput.value.trim() || 'right';
    if (!leftText && !rightText) {
      toast('Load or paste at least one side.', 'warn');
      return;
    }
    comparison = await buildFileComparison(leftPath, leftText, rightPath, rightText);
    output.innerHTML = renderComparison(comparison);
    wireCopyButtons(output);
  });

  view.querySelector('#run-snapshot-compare')?.addEventListener('click', () => {
    snapshotId = view.querySelector('#snapshot-id').value;
    const snapshot = getSnapshot(snapshotId);
    if (!snapshot) {
      toast('Snapshot not found.', 'danger');
      return;
    }
    snapshotFile = null;
    renderSnapshot(snapshot, view, (filePath) => {
      snapshotFile = filePath;
      renderSnapshot(snapshot, view, () => {}, snapshotFile);
    }, snapshotFile);
  });

  if (mode === 'snapshot' && snapshotId && history.length && workspace) {
    const snapshot = getSnapshot(snapshotId);
    if (snapshot) {
      // Render the file list immediately for the selected snapshot; the actual
      // diffs are generated on demand to keep the page fast.
      renderSnapshot(snapshot, view, (filePath) => {
        snapshotFile = filePath;
        renderSnapshot(snapshot, view, () => {}, snapshotFile);
      }, null);
    }
  }

  return null;
}

function fileKind(path, text) {
  return detectFileKind(path, text);
}

async function buildFileComparison(leftPath, leftText, rightPath, rightText) {
  const leftKind = fileKind(leftPath, leftText);
  const rightKind = fileKind(rightPath, rightText);
  const operations = lineDiff(leftText, rightText);
  const result = {
    leftPath,
    rightPath,
    leftText,
    rightText,
    leftKind,
    rightKind,
    operations,
    semantic: null,
    parser: null,
  };
  if (leftKind === 'zone' && rightKind === 'zone') {
    const leftZone = parseZone(leftText, { origin: inferZoneOrigin(leftPath, leftText), file: leftPath });
    const rightZone = parseZone(rightText, { origin: inferZoneOrigin(rightPath, rightText), file: rightPath });
    result.semantic = { type: 'zone', diff: semanticZoneDiff(leftZone, rightZone), leftZone, rightZone };
  } else if (leftKind === 'named' && rightKind === 'named') {
    const leftNamed = parseNamed(leftText, { file: leftPath });
    const rightNamed = parseNamed(rightText, { file: rightPath });
    result.semantic = { type: 'named', diff: semanticNamedDiff({ named: { statements: leftNamed.statements } }, { named: { statements: rightNamed.statements } }), leftNamed, rightNamed };
  } else {
    result.parser = {
      left: leftKind === 'zone' ? parseZone(leftText, { origin: inferZoneOrigin(leftPath, leftText), file: leftPath }) : leftKind === 'named' ? parseNamed(leftText, { file: leftPath }) : null,
      right: rightKind === 'zone' ? parseZone(rightText, { origin: inferZoneOrigin(rightPath, rightText), file: rightPath }) : rightKind === 'named' ? parseNamed(rightText, { file: rightPath }) : null,
    };
  }
  return result;
}

function renderComparison(result) {
  const stats = result.operations.filter((operation) => operation.type === 'add').length;
  const removed = result.operations.filter((operation) => operation.type === 'del').length;
  return `<div class="compare-result-head">
    <div><h2>${escapeHTML(result.leftPath)} <span class="muted">→</span> ${escapeHTML(result.rightPath)}</h2><p>${result.leftKind} → ${result.rightKind} · ${formatNumber(stats)} line${stats === 1 ? '' : 's'} added · ${formatNumber(removed)} removed</p></div>
    <div class="meta-strip">${pill(result.leftKind, 'neutral', 'file')}${pill(result.rightKind, 'neutral', 'file')}${pill(`${stats + removed} changed lines`, stats + removed ? 'warn' : 'ok', 'diff')}</div>
  </div>
  ${renderSemantic(result)}
  <div class="section-head small"><h2>Line diff</h2><p>Old and new line numbers are shown side by side.</p></div>
  ${renderDiff(result.operations)}
  ${renderParserNotes(result)}`;
}

function renderSemantic(result) {
  if (!result.semantic) {
    return `<div class="callout info">${icon('info', 18)}<div><strong>Text comparison only</strong><p>One or both files are not zone or named.conf files, so the semantic view is unavailable. Use the line diff below.</p></div></div>`;
  }
  if (result.semantic.type === 'zone') {
    const diff = result.semantic.diff;
    return `<div class="semantic-card">
      <div class="semantic-head"><h3>${icon('database', 17)} Semantic zone diff</h3><div class="meta-strip">${pill(`${diff.counts.added} added`, diff.counts.added ? 'ok' : 'neutral', 'plus')}${pill(`${diff.counts.removed} removed`, diff.counts.removed ? 'danger' : 'neutral', 'trash')}${pill(`${diff.counts.ttlChanged} TTL changes`, diff.counts.ttlChanged ? 'warn' : 'neutral', 'clock')}</div></div>
      ${diff.serialChange ? `<div class="callout ${diff.serialChange.after > diff.serialChange.before ? 'ok' : 'warn'}">${icon('clock', 18)}<div><strong>SOA serial ${escapeHTML(diff.serialChange.before)} → ${escapeHTML(diff.serialChange.after)}</strong><p>${diff.serialChange.after > diff.serialChange.before ? 'The serial increased, which secondaries will notice.' : 'The serial did not increase. Secondaries may ignore this change. Fix the serial before deploying.'}</p></div></div>` : ''}
      ${diff.soaChanges?.length ? `<div class="callout info">${icon('info', 18)}<div><strong>Other SOA changes</strong><ul>${diff.soaChanges.map((item) => `<li><code>${escapeHTML(item.field)}</code>: ${escapeHTML(String(item.before))} → ${escapeHTML(String(item.after))}</li>`).join('')}</ul></div></div>` : ''}
      ${diff.added.length ? `<h4>Added records</h4><div class="table-scroll"><table class="record-table compact"><thead><tr><th>Owner</th><th>TTL</th><th>Type</th><th>RDATA</th></tr></thead><tbody>${diff.added.map((record) => `<tr><td><code>${escapeHTML(record.owner)}</code></td><td>${record.ttl ?? '—'}</td><td><span class="record-type">${escapeHTML(record.type)}</span></td><td><code>${escapeHTML(record.rdata)}</code></td></tr>`).join('')}</tbody></table></div>` : ''}
      ${diff.removed.length ? `<h4>Removed records</h4><div class="table-scroll"><table class="record-table compact"><thead><tr><th>Owner</th><th>TTL</th><th>Type</th><th>RDATA</th></tr></thead><tbody>${diff.removed.map((record) => `<tr><td><code>${escapeHTML(record.owner)}</code></td><td>${record.ttl ?? '—'}</td><td><span class="record-type">${escapeHTML(record.type)}</span></td><td><code>${escapeHTML(record.rdata)}</code></td></tr>`).join('')}</tbody></table></div>` : ''}
      ${diff.ttlChanged.length ? `<h4>TTL changes</h4><ul>${diff.ttlChanged.map((item) => `<li><code>${escapeHTML(item.record.owner)} ${escapeHTML(item.record.type)}</code> — ${escapeHTML(String(item.before))} → ${escapeHTML(String(item.after))} seconds</li>`).join('')}</ul>` : ''}
    </div>`;
  }
  const diff = result.semantic.diff;
  return `<div class="semantic-card"><div class="semantic-head"><h3>${icon('file', 17)} Semantic named.conf diff</h3><div class="meta-strip">${pill(`${diff.counts.added} added`, diff.counts.added ? 'ok' : 'neutral', 'plus')}${pill(`${diff.counts.removed} removed`, diff.counts.removed ? 'danger' : 'neutral', 'trash')}</div></div>
    ${diff.added.length ? `<h4>Added statements</h4><ul>${diff.added.map((statement) => `<li><code>${escapeHTML(statement.keyword)} ${escapeHTML((statement.args || []).join(' '))}</code> at ${escapeHTML(statement.file)}:${statement.line}</li>`).join('')}</ul>` : ''}
    ${diff.removed.length ? `<h4>Removed statements</h4><ul>${diff.removed.map((statement) => `<li><code>${escapeHTML(statement.keyword)} ${escapeHTML((statement.args || []).join(' '))}</code> at ${escapeHTML(statement.file)}:${statement.line}</li>`).join('')}</ul>` : ''}
    ${!diff.added.length && !diff.removed.length ? '<p class="muted">No directive-level changes detected (comments and ordering are ignored by the semantic view).</p>' : ''}
  </div>`;
}

function renderParserNotes(result) {
  if (!result.parser) return '';
  const notes = [];
  if (result.parser.left?.errors?.length) notes.push(`Left parser: ${result.parser.left.errors.length} error(s)`);
  if (result.parser.right?.errors?.length) notes.push(`Right parser: ${result.parser.right.errors.length} error(s)`);
  if (!notes.length) return '';
  return `<div class="callout warn">${icon('warning', 18)}<div><strong>Parser notes</strong><p>${notes.map(escapeHTML).join(' · ')}. The line diff still shows the text, but semantic data may be incomplete.</p></div></div>`;
}

function renderSnapshot(snapshot, view, onSelect, selectedFile) {
  const current = getCurrentWorkspace();
  if (!current) return;
  const changed = changedFilePaths(snapshot.workspace, current);
  const output = view.querySelector('#snapshot-output');
  if (!changed.length) {
    output.innerHTML = `<div class="callout ok">${icon('check', 18)}<div><strong>No changes</strong><p>The snapshot and the current workspace contain identical file contents.</p></div></div>`;
    return;
  }
  const active = selectedFile || changed[0];
  const fileMeta = new Map(changed.map((path) => {
    const old = snapshot.workspace.files.find((file) => file.path === path) || null;
    const next = current.files.find((file) => file.path === path) || null;
    return [path, { old, next }];
  }));
  const oldFile = fileMeta.get(active)?.old || null;
  const newFile = fileMeta.get(active)?.next || null;
  const oldText = oldFile?.content ?? '';
  const newText = newFile?.content ?? '';
  const oldKind = detectFileKind(active, oldText);
  const newKind = detectFileKind(active, newText);
  const operations = lineDiff(oldText, newText);
  let semantic = '';
  if (oldKind === 'zone' && newKind === 'zone') {
    const diff = semanticZoneDiff(parseZone(oldText, { origin: inferZoneOrigin(active, oldText), file: active }), parseZone(newText, { origin: inferZoneOrigin(active, newText), file: active }));
    semantic = renderSemantic({ semantic: { type: 'zone', diff } });
  }
  output.innerHTML = `<div class="snapshot-banner">${icon('clock', 18)}<div><strong>${escapeHTML(snapshot.name)}</strong><p>Snapshot ${escapeHTML(formatDateTime(snapshot.createdAt))} · ${changed.length} changed file(s) · compared with current workspace</p></div>${pill(snapshot.label || snapshot.source, 'neutral', 'save')}</div>
    <div class="snapshot-layout">
      <aside class="snapshot-files">${changed.map((path) => {
        const meta = fileMeta.get(path);
        return `<button class="snapshot-file ${path === active ? 'active' : ''}" type="button" data-snapshot-file="${escapeHTML(path)}">${icon(meta?.old?.kind === 'zone' || meta?.next?.kind === 'zone' ? 'database' : 'file', 14)}<span>${escapeHTML(path)}</span>${!meta?.next ? pill('deleted', 'danger') : !meta?.old ? pill('added', 'ok') : ''}</button>`;
      }).join('')}</aside>
      <div class="snapshot-diff"><div class="snapshot-diff-head"><strong>${escapeHTML(active)}</strong><span>${oldFile ? 'old' : 'missing'} → ${newFile ? 'new' : 'missing'}</span></div>${semantic}<div class="section-head small"><h2>Line diff</h2></div>${renderDiff(operations)}</div>
    </div>`;
  output.querySelectorAll('[data-snapshot-file]').forEach((button) => {
    button.addEventListener('click', () => onSelect(button.dataset.snapshotFile));
  });
  wireCopyButtons(output);
}

// Re-export the helpers used by tests / future pages.
export { semanticZoneDiff, semanticNamedDiff };
