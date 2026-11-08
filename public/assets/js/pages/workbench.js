/* Multi-file workbench: editor, structure, zones and in-context learning. */

import { analyzeWorkspace } from '../dns/analyzer.js';
import { downloadWorkspaceFile, downloadWorkspaceJson, downloadWorkspaceZip } from '../dns/export.js';
import { getCurrentWorkspace, saveCurrentWorkspace, saveSnapshot } from '../storage.js';
import {
  detectFileKind,
  fileByPath,
  fileKindLabel,
  guessEntryFile,
  makeWorkspaceFile,
  parseWorkspace,
} from '../dns/workspace.js';
import { directiveDoc } from '../data/directives.js';
import { recordDoc } from '../data/records.js';
import { zoneDnssecInventory } from '../dns/dnssec.js';
import { icon, openModal, pill, toast, confirmDialog, wireCopyButtons } from '../ui.js';
import { formatTTL } from '../dns/syntax.js';
import { escapeHTML, formatBytes, formatNumber, lineCount, shellQuote } from '../utils.js';
import { wireImportControls } from './import-ui.js';

export async function renderWorkbench(view, param, query) {
  let workspace = getCurrentWorkspace();
  let model = null;
  let analysis = null;
  let activeFileId = null;
  let activeTab = query.get('tab') || 'source';
  if (!['source', 'structure', 'zones', 'learn'].includes(activeTab)) activeTab = 'source';
  let pendingLine = Number(query.get('line') || 0) || null;
  let exportHandled = query.get('export') !== '1';
  let dirty = false;
  let disposed = false;
  let parseTimer = null;
  let analysisTimer = null;
  let saveTimer = null;
  let editor = null;
  let lineNumbers = null;
  let validationPanel = null;
  const cleanups = [];

  if (!workspace) {
    view.innerHTML = workspaceEmptyState();
    wireImportControls(view, { navigate: false, onImported: () => window.dispatchEvent(new Event('workbench:reload')) });
    return null;
  }

  function fileById(id) {
    return workspace.files.find((file) => file.id === id) || null;
  }

  function selectInitialFile() {
    const requested = query.get('file');
    if (requested) {
      const found = fileByPath(workspace, requested);
      if (found) {
        activeFileId = found.id;
        return;
      }
    }
    const entry = fileByPath(workspace, workspace.entry) || workspace.files.find((file) => file.kind === 'named') || workspace.files[0];
    activeFileId = entry?.id || null;
  }

  function activeFile() {
    return fileById(activeFileId);
  }

  function parseNow() {
    model = parseWorkspace(workspace);
  }

  async function analyzeNow() {
    if (!model) parseNow();
    analysis = await analyzeWorkspace(workspace, model);
  }

  function saveWorkspaceNow() {
    if (!workspace) return;
    workspace.updatedAt = new Date().toISOString();
    const result = saveCurrentWorkspace(workspace);
    if (!result.ok) toast(result.error || 'Could not save locally.', 'danger');
    dirty = false;
  }

  function snapshot(label = 'Manual save', source = 'save') {
    saveWorkspaceNow();
    const result = saveSnapshot(workspace, { label, source, analysis: analysis ? { ...analysis, zones: model?.zones?.length } : null });
    if (!result.ok) toast(result.error || 'Could not create a snapshot.', 'danger');
    else toast(result.deduplicated ? 'Snapshot updated (content unchanged).' : 'Snapshot saved to local history.', 'ok');
  }

  function markDirty() {
    dirty = true;
    const status = view.querySelector('#save-status');
    if (status) {
      status.classList.add('dirty');
      status.querySelector('span:last-child').textContent = 'Saving locally…';
    }
    clearTimeout(saveTimer);
    saveTimer = setTimeout(() => {
      saveWorkspaceNow();
      const node = view.querySelector('#save-status');
      if (node) {
        node.classList.remove('dirty');
        node.querySelector('span:last-child').textContent = 'Saved locally';
      }
    }, 450);
  }

  function selectedFileFromEditor() {
    const file = activeFile();
    if (!file || !editor) return;
    if (file.content === editor.value) return;
    file.content = editor.value;
    file.size = new TextEncoder().encode(file.content).length;
    file.updatedAt = new Date().toISOString();
    if (disposed) return;
    markDirty();
    scheduleParse();
  }

  function scheduleParse() {
    clearTimeout(parseTimer);
    clearTimeout(analysisTimer);
    parseTimer = setTimeout(() => {
      if (disposed) return;
      selectedFileFromEditor();
      parseNow();
      updateStats();
      updateEditorChrome();
      updateValidationPanel();
      analysisTimer = setTimeout(async () => {
        if (disposed) return;
        await analyzeNow();
        updateStats();
        updateValidationPanel();
      }, 700);
    }, 260);
  }

  function setTab(tab) {
    if (!['source', 'structure', 'zones', 'learn'].includes(tab)) tab = 'source';
    activeTab = tab;
    pendingLine = null;
    paint();
  }

  function setFile(id, line = null) {
    activeFileId = id;
    pendingLine = line || null;
    activeTab = 'source';
    paint();
  }

  function updateEditorChrome() {
    if (!editor) return;
    const count = lineCount(editor.value);
    if (lineNumbers) {
      lineNumbers.textContent = Array.from({ length: Math.max(1, count) }, (_, index) => index + 1).join('\n');
      lineNumbers.scrollTop = editor.scrollTop;
    }
    const metrics = view.querySelector('#editor-metrics');
    if (metrics) {
      metrics.innerHTML = `<span>${formatNumber(count)} lines</span><span>${formatBytes(new TextEncoder().encode(editor.value).length)}</span><span>${escapeHTML(activeFile()?.path || '')}</span>`;
    }
    const footer = view.querySelector('#editor-footer');
    if (footer) {
      footer.innerHTML = `<span>${icon('file', 13)} ${escapeHTML(activeFile()?.path || '')}</span><span>${icon('info', 13)} BIND master-file syntax: semicolons start comments; parentheses join records.</span>`;
    }
  }

  function updateStats() {
    if (!model) parseNow();
    if (!analysis) {
      // The first analysis may still be running; show parser-derived counts.
    }
    const node = view.querySelector('#wb-stats');
    if (!node) return;
    const counts = analysis?.counts || { error: model.summary.errors, warning: model.summary.warnings, recommendation: 0 };
    const score = analysis?.score ?? null;
    node.innerHTML = `
      ${pill(`${model.summary.files} files`, 'neutral', 'file')}
      ${pill(`${model.summary.zones} zones`, 'accent', 'database')}
      ${pill(`${formatNumber(model.summary.records)} records`, 'neutral', 'list')}
      ${pill(`${counts.error} errors`, counts.error ? 'danger' : 'ok', counts.error ? 'error' : 'check')}
      ${pill(`${counts.warning} warnings`, counts.warning ? 'warn' : 'ok', 'warning')}
      ${score === null ? '' : `<span class="score-inline ${score < 60 ? 'danger' : score < 80 ? 'warn' : 'ok'}">${score}<small>score</small></span>`}
    `;
    const status = view.querySelector('#analysis-status');
    if (status) {
      status.textContent = analysis ? `Analyzed ${new Date(analysis.analyzedAt).toLocaleTimeString(undefined, { hourCycle: 'h23' })}` : 'Analysis pending…';
    }
  }

  function fileFindings(file) {
    if (!analysis || !file) return [];
    return analysis.findings.filter((finding) => finding.file === file.path || finding.zone === file.path);
  }

  function updateValidationPanel() {
    if (!validationPanel) return;
    const file = activeFile();
    if (!file) {
      validationPanel.innerHTML = '';
      return;
    }
    const findings = fileFindings(file).slice(0, 10);
    const parseErrors = (model?.named?.parseErrors || []).filter((error) => error.file === file.path);
    const zoneErrors = (model?.zoneErrors || []).filter((error) => error.file === file.path);
    const total = findings.length + parseErrors.length + zoneErrors.length;
    if (!total) {
      validationPanel.innerHTML = `<div class="validation-head"><div>${icon('check', 15)} <strong>No problems found in this file</strong></div><span class="muted-note">Static analysis only; run named-checkconf/zone for the final gate.</span></div>`;
      return;
    }
    const items = [
      ...parseErrors.map((error) => ({ severity: 'error', title: 'Syntax', message: error.message, line: error.line })),
      ...zoneErrors.map((error) => ({ severity: 'error', title: 'Zone syntax', message: error.message, line: error.line })),
      ...findings.map((finding) => ({ severity: finding.severity, title: finding.title, message: finding.message, line: finding.line, id: finding.id })),
    ].slice(0, 8);
    validationPanel.innerHTML = `<div class="validation-head">
      <div>${icon('warning', 15)} <strong>${formatNumber(total)} finding${total === 1 ? '' : 's'} in this file</strong>${findings.length > items.length ? `<span class="muted-note">showing ${items.length}</span>` : ''}</div>
      <a class="btn btn-xs" href="#/analyze">${icon('shield', 13)} Open analysis</a>
    </div>
    <ul class="validation-list">${items.map((item) => `<li><span class="sev-dot ${item.severity}"></span><span>${escapeHTML(item.title)}: ${escapeHTML(item.message)}</span>${item.line ? `<button class="button-like" type="button" data-goto-line="${item.line}">line ${item.line}</button>` : ''}</li>`).join('')}</ul>`;
    validationPanel.querySelectorAll('[data-goto-line]').forEach((button) => {
      button.addEventListener('click', () => jumpToLine(Number(button.dataset.gotoLine)));
    });
  }

  function jumpToLine(line) {
    if (!editor) return;
    const lines = editor.value.split('\n');
    const target = Math.max(0, Math.min(lines.length - 1, line - 1));
    const offset = lines.slice(0, target).reduce((sum, value) => sum + value.length + 1, 0);
    editor.focus();
    editor.setSelectionRange(offset, offset + (lines[target]?.length || 0));
    const lineHeight = parseFloat(getComputedStyle(editor).lineHeight) || 20;
    editor.scrollTop = Math.max(0, target * lineHeight - editor.clientHeight / 2);
    if (lineNumbers) lineNumbers.scrollTop = editor.scrollTop;
  }

  function editorHtml() {
    const file = activeFile();
    if (!file) {
      return `<div class="empty-panel"><h2>No file selected</h2><p>Add a file or import a workspace to begin.</p><button class="btn btn-primary" type="button" data-add-file>${icon('plus', 15)} Add file</button></div>`;
    }
    const findings = analysis?.findings?.filter((finding) => finding.file === file.path).length || 0;
    return `<div class="editor-toolbar">
      <div class="editor-toolbar-left">
        <span class="editor-lang">${escapeHTML(fileKindLabel(file.kind))}</span>
        <strong class="mono">${escapeHTML(file.path)}</strong>
        ${workspace.entry === file.path ? pill('entry', 'accent', 'star') : ''}
        ${findings ? pill(`${findings} findings`, 'warn', 'warning') : ''}
      </div>
      <div class="editor-toolbar-right">
        <button class="btn btn-sm btn-ghost" type="button" data-file-download>${icon('download', 14)} File</button>
        <button class="btn btn-sm btn-ghost" type="button" data-file-rename>${icon('edit', 14)} Rename</button>
        <button class="btn btn-sm btn-ghost" type="button" data-file-delete>${icon('trash', 14)} Delete</button>
        ${workspace.entry !== file.path && file.kind === 'named' ? `<button class="btn btn-sm btn-ghost" type="button" data-file-entry>${icon('star', 14)} Set entry</button>` : ''}
      </div>
    </div>
    <div class="editor-shell">
      <pre class="line-numbers" id="line-numbers" aria-hidden="true"></pre>
      <textarea class="config-editor" id="config-editor" spellcheck="false" autocapitalize="off" autocomplete="off" wrap="off" aria-label="Configuration source editor"></textarea>
    </div>
    <div class="editor-footer" id="editor-footer"></div>
    <div class="validation-panel" id="validation-panel"></div>`;
  }

  function renderStatement(statement, depth = 0) {
    const args = (statement.args || []).join(' ');
    const doc = directiveDoc(statement.keyword);
    const body = statement.body?.length
      ? `<div class="statement-children">${statement.body.map((child) => renderStatement(child, depth + 1)).join('')}</div>`
      : '';
    return `<details class="statement" ${depth === 0 ? 'open' : ''}>
      <summary>
        <span class="line-no">${statement.line}</span>
        <code class="statement-key">${escapeHTML(statement.keyword)}</code>
        ${args ? `<code class="statement-args">${escapeHTML(args)}</code>` : ''}
        ${doc ? pill(doc.name, 'neutral') : ''}
        <button class="button-like line-jump" type="button" data-goto-file="${escapeHTML(statement.file)}" data-goto-line="${statement.line}">${escapeHTML(statement.file.split('/').pop())}:${statement.line}</button>
        <span class="chev">${icon('chevron', 15)}</span>
      </summary>
      <div class="statement-body">
        ${doc ? `<p class="muted">${escapeHTML(doc.summary)}</p>` : ''}
        ${statement.body?.length ? body : ''}
        ${statement.hasBlock && !statement.body?.length ? '<p class="muted-note">Empty block.</p>' : ''}
      </div>
    </details>`;
  }

  function structureHtml() {
    if (!model?.named?.statements?.length) {
      return `<div class="empty-panel"><h2>No named.conf structure</h2><p>This workspace contains zone data only. Add a named.conf to unlock include, view, ACL and zone-policy analysis.</p></div>`;
    }
    const unresolved = model.includes.filter((item) => !item.resolved);
    return `<div class="structure-overview">
      <div>${pill(model.entryFile || 'no entry', 'accent', 'file')} ${pill(`${model.includes.length} includes`, unresolved.length ? 'warn' : 'ok', 'layers')} ${pill(`${model.views.length} views`, 'neutral', 'layers')} ${pill(`${model.keys.length} keys`, 'neutral', 'key')}</div>
      <div class="structure-tips">${icon('info', 14)} Click a line link to open that exact file and line. Details are collapsed for nested blocks.</div>
    </div>
    ${unresolved.length ? `<div class="callout warn">${icon('warning', 18)}<div><strong>Unresolved includes</strong><ul>${unresolved.map((item) => `<li><code>${escapeHTML(item.requested)}</code> from ${escapeHTML(item.from)}:${item.line}</li>`).join('')}</ul></div></div>` : ''}
    <div class="structure-list">${model.named.statements.map((statement) => renderStatement(statement)).join('')}</div>`;
  }

  function zoneFindingList(zone) {
    if (!analysis) return [];
    return analysis.findings.filter((finding) => finding.zone === zone.name || (finding.file && finding.file === zone.filePath));
  }

  function zoneHtml(zone, index) {
    const parsed = zone.parsed;
    const inventory = zoneDnssecInventory(parsed);
    const findings = zoneFindingList(zone);
    const records = parsed?.records || [];
    const errors = findings.filter((finding) => finding.severity === 'error').length;
    const warnings = findings.filter((finding) => finding.severity === 'warning').length;
    const types = Array.from(new Set(records.map((record) => record.type))).sort();
    const renderedRecords = records.slice(0, 2000);
    const rows = renderedRecords.map((record) => {
      const search = `${record.owner} ${record.type} ${record.rdata} ${record.ttl || ''}`.toLowerCase();
      return `<tr data-record-row data-search="${escapeHTML(search)}" data-record-type="${escapeHTML(record.type)}">
        <td class="row-line"><button class="button-like" type="button" data-goto-file="${escapeHTML(record.file)}" data-goto-line="${record.line}">${record.line}</button></td>
        <td><code>${escapeHTML(record.owner)}</code></td>
        <td class="mono">${record.ttl === null ? '<span class="text-warn">—</span>' : escapeHTML(formatTTL(record.ttl))}</td>
        <td><span class="record-type">${escapeHTML(record.type)}</span></td>
        <td class="record-data"><code>${escapeHTML(record.rdata)}</code></td>
        <td>${recordDoc(record.type) ? `<a class="learn-link" href="#/reference?tab=records&q=${encodeURIComponent(record.type)}" title="${escapeHTML(recordDoc(record.type).summary)}">${icon('book', 13)}</a>` : ''}</td>
      </tr>`;
    }).join('');
    return `<article class="zone-card" id="zone-${index}">
      <div class="zone-head">
        <div class="zone-title">
          ${icon('database', 20)}
          <div><h2>${escapeHTML(zone.name)}</h2><p>${escapeHTML(zone.type || 'unknown type')}${zone.view ? ` · view ${escapeHTML(zone.view)}` : ''}${zone.synthetic ? ' · standalone file' : ''}</p></div>
        </div>
        <div class="zone-metrics">
          ${pill(`${records.length} records`, 'neutral', 'list')}
          ${pill(`SOA ${parsed?.soa?.data?.serial ?? 'missing'}`, parsed?.soa ? 'accent' : 'danger', 'clock')}
          ${pill(`${inventory.keys.length} DNSKEY`, inventory.keys.length ? 'ok' : 'neutral', 'key')}
          ${pill(`${inventory.rrsigs.length} RRSIG`, inventory.rrsigs.length ? 'ok' : 'neutral', 'shield')}
          ${errors ? pill(`${errors} errors`, 'danger', 'error') : ''}
          ${warnings ? pill(`${warnings} warnings`, 'warn', 'warning') : ''}
        </div>
        <div class="zone-actions">
          ${zone.filePath ? `<button class="btn btn-sm btn-ghost" type="button" data-goto-file="${escapeHTML(zone.filePath)}" data-goto-line="1">${icon('code', 14)} Open file</button>` : ''}
          <a class="btn btn-sm" href="#/live?tab=verify&zone=${encodeURIComponent(zone.name)}">${icon('globe', 14)} Verify live</a>
          ${zone.filePath ? `<button class="btn btn-sm btn-ghost" type="button" data-copy="${escapeHTML(`named-checkzone ${shellQuote(zone.name)} ${shellQuote(zone.filePath)}`)}">${icon('terminal', 14)} named-checkzone</button>` : ''}
        </div>
      </div>
      <div class="zone-body">
        ${findings.length ? `<div class="zone-findings">${findings.slice(0, 8).map((finding) => `<div class="zone-finding ${finding.severity}"><span class="sev-dot ${finding.severity}"></span><div><strong>${escapeHTML(finding.title)}</strong><span>${escapeHTML(finding.message)}</span></div>${finding.line ? `<button class="button-like" type="button" data-goto-file="${escapeHTML(finding.file)}" data-goto-line="${finding.line}">line ${finding.line}</button>` : ''}</div>`).join('')}</div>` : `<div class="zone-ok">${icon('check', 15)} No analyzer findings for this zone.</div>`}
        <div class="zone-records-toolbar">
          <div class="search-field">${icon('search', 15)}<input type="search" placeholder="Filter by name, type or data…" data-zone-search="${index}" aria-label="Filter records"></div>
          <select class="select" data-zone-type="${index}" aria-label="Filter by record type"><option value="">All types</option>${types.map((type) => `<option value="${escapeHTML(type)}">${escapeHTML(type)}</option>`).join('')}</select>
          <span class="filter-result" data-zone-count="${index}">${formatNumber(records.length)} records</span>
        </div>
        <div class="table-scroll">
          <table class="record-table">
            <thead><tr><th>Line</th><th>Owner</th><th>TTL</th><th>Type</th><th>RDATA</th><th></th></tr></thead>
            <tbody>${rows || '<tr><td colspan="6" class="muted">No records parsed for this zone.</td></tr>'}</tbody>
          </table>
        </div>
        <div class="zone-foot">${zone.filePath ? `<span>${icon('file', 13)} ${escapeHTML(zone.filePath)}</span>` : '<span>Zone data not available in this workspace.</span>'}
          ${parsed?.soa ? `<span>SOA ${escapeHTML(parsed.soa.data.mname)} / ${escapeHTML(parsed.soa.data.rname)}</span>` : ''}
          <span>Denial: ${escapeHTML(inventory.denial)}</span>
          ${records.length > renderedRecords.length ? `<span>Showing first ${formatNumber(renderedRecords.length)} of ${formatNumber(records.length)} records</span>` : ''}
        </div>
      </div>
    </article>`;
  }

  function zonesHtml() {
    if (!model?.zones?.length) {
      return `<div class="empty-panel"><h2>No zones found</h2><p>Add a zone declaration and its file, or import a zone file directly. A zone-only workspace is parsed with an inferred origin.</p><button class="btn btn-primary" type="button" data-add-file>${icon('plus', 15)} Add file</button></div>`;
    }
    return `<div class="zone-summary-strip">
      ${pill(`${model.zones.length} zones`, 'accent', 'database')}
      ${pill(`${formatNumber(model.summary.records)} records`, 'neutral', 'list')}
      ${pill(`${model.zones.filter((zone) => zone.parsed?.soa).length} with SOA`, 'ok', 'check')}
      ${pill(`${model.zones.filter((zone) => zoneDnssecInventory(zone.parsed).signed).length} signed`, 'ok', 'shield')}
      ${pill(`${model.zones.filter((zone) => !zone.filePath).length} without files`, 'warn', 'warning')}
    </div>
    <div class="zone-list">${model.zones.map((zone, index) => zoneHtml(zone, index)).join('')}</div>`;
  }

  function learnHtml() {
    if (!model) return '';
    const flat = model.named?.statements?.length ? flattenForLearn(model.named.statements) : [];
    const byFile = new Map();
    for (const item of flat.slice(0, 240)) {
      if (!byFile.has(item.statement.file)) byFile.set(item.statement.file, []);
      byFile.get(item.statement.file).push(item);
    }
    const types = Array.from(new Set((model.zones || []).flatMap((zone) => (zone.parsed?.records || []).map((record) => record.type)))).sort();
    const recordCards = types.map((type) => {
      const doc = recordDoc(type);
      return `<a class="record-doc-card" href="#/reference?tab=records&q=${encodeURIComponent(type)}">
        <span class="record-type">${escapeHTML(type)}</span>
        <strong>${escapeHTML(doc?.name || type)}</strong>
        <p>${escapeHTML(doc?.summary || 'Record type present in this workspace.')}</p>
      </a>`;
    }).join('');
    return `<div class="learn-config-intro">
      <div><span class="eyebrow">Learn this config</span><h2>Every directive in context</h2><p>Each row is a real statement from your workspace. The explanation is keyed by directive and context, not a generic manual page. Use the source link to jump to it.</p></div>
      <div class="learn-config-stats"><div><strong>${flat.length}</strong><span>statements</span></div><div><strong>${types.length}</strong><span>record types</span></div><div><strong>${model.keys.length}</strong><span>keys</span></div><div><strong>${model.views.length}</strong><span>views</span></div></div>
    </div>
    ${recordCards ? `<div class="section-head small"><h2>Record types in this workspace</h2><p>Click a record for fields, gotchas and DNSSEC notes.</p></div><div class="record-doc-grid">${recordCards}</div>` : ''}
    <div class="learn-config-list">${Array.from(byFile.entries()).map(([file, items]) => `<section class="learn-config-section">
      <div class="learn-section-head"><div class="learn-section-title">${icon('file', 16)}<h2>${escapeHTML(file)}</h2><span class="muted">${items.length} statement${items.length === 1 ? '' : 's'}</span></div></div>
      <div class="learn-rows">${items.map(({ statement, context }) => {
        const doc = directiveDoc(statement.keyword);
        return `<div class="learn-row">
          <div class="learn-line-no">${statement.line}</div>
          <div class="learn-row-main">
            <div class="learn-row-head"><code class="directive-code"><span class="kw">${escapeHTML(statement.keyword)}</span>${statement.args?.length ? ` ${escapeHTML(statement.args.join(' '))}` : ''}</code><button class="button-like" type="button" data-goto-file="${escapeHTML(statement.file)}" data-goto-line="${statement.line}">open</button></div>
            <p class="learn-context">${context.length ? `inside ${escapeHTML(context.join(' → '))}` : 'top level'}${doc ? ` · ${escapeHTML(doc.context)}` : ''}</p>
            <p class="learn-summary">${escapeHTML(doc?.summary || 'No encyclopedia entry yet; the statement is preserved exactly as written.')}</p>
            ${doc ? `<details class="learn-detail"><summary>What, why and gotchas</summary><p>${escapeHTML(doc.what)}</p>${doc.security ? `<p><strong>Security:</strong> ${escapeHTML(doc.security)}</p>` : ''}${doc.gotchas?.length ? `<ul>${doc.gotchas.map((item) => `<li>${escapeHTML(item)}</li>`).join('')}</ul>` : ''}<a class="learn-link" href="#/reference?q=${encodeURIComponent(statement.keyword)}">Full reference ${icon('arrow', 13)}</a></details>` : ''}
          </div>
        </div>`;
      }).join('')}</div>
    </section>`).join('')}</div>
    ${flat.length > 240 ? `<p class="muted-note">Showing the first 240 statements. Use the Structure tab for the complete tree.</p>` : ''}`;
  }

  function flattenForLearn(statements, context = [], output = []) {
    for (const statement of statements) {
      output.push({ statement, context });
      if (statement.body?.length) flattenForLearn(statement.body, [...context, statement.keyword], output);
    }
    return output;
  }

  function panelHtml() {
    switch (activeTab) {
      case 'structure': return structureHtml();
      case 'zones': return zonesHtml();
      case 'learn': return learnHtml();
      default: return editorHtml();
    }
  }

  function shellHtml() {
    return `<div class="page-head workbench-head">
      <div class="page-head-copy">
        <span class="eyebrow">Workspace</span>
        <h1>${escapeHTML(workspace.name)}</h1>
        <p class="page-lede">Edit the real files, follow includes, inspect every zone record and learn each directive in context.</p>
        <div class="meta-strip" id="wb-stats"></div>
      </div>
      <div class="page-actions">
        <button class="btn btn-primary" type="button" data-import-files>${icon('upload', 16)} Import</button>
        <button class="btn" type="button" data-export-bundle>${icon('package', 16)} Export bundle</button>
        <button class="btn btn-ghost" type="button" data-save-snapshot>${icon('save', 16)} Save snapshot</button>
        <a class="btn btn-ghost" href="#/analyze">${icon('shield', 16)} Analyze</a>
      </div>
    </div>
    <div data-upload-gate></div>
    <div class="workbench-shell">
      <aside class="file-rail" aria-label="Workspace files">
        <div class="file-rail-head">
          <div><strong>Files</strong><span>${workspace.files.length} total</span></div>
          <button class="btn btn-icon" type="button" data-add-file title="Add a file" aria-label="Add a file">${icon('plus', 17)}</button>
        </div>
        <div class="file-list">
          ${workspace.files.map((item) => `<button class="file-item ${item.id === activeFileId ? 'active' : ''}" type="button" data-file-id="${escapeHTML(item.id)}">
            ${icon(item.kind === 'zone' ? 'database' : item.kind === 'named' ? 'file' : 'code', 15)}
            <span class="file-item-main"><strong>${escapeHTML(item.name)}</strong><small>${escapeHTML(item.path)}</small></span>
            <span class="file-badges">${workspace.entry === item.path ? '<span class="mini-badge accent">entry</span>' : ''}${item.content !== item.originalContent ? '<span class="mini-badge warn">edited</span>' : ''}</span>
          </button>`).join('')}
        </div>
        <div class="file-rail-foot">
          <span id="save-status"><span class="save-dot"></span><span>${dirty ? 'Unsaved' : 'Saved locally'}</span></span>
          <a href="#/history">${icon('clock', 13)} History</a>
        </div>
        ${model?.includes?.length ? `<div class="include-mini"><strong>${icon('layers', 13)} Includes</strong>${model.includes.map((item) => `<div class="include-row ${item.resolved ? '' : 'missing'}">${item.resolved ? icon('check', 12) : icon('warning', 12)}<span title="${escapeHTML(item.from)}:${item.line}">${escapeHTML(item.requested)}</span><small>${item.resolved ? escapeHTML(item.path.split('/').pop()) : 'missing'}</small></div>`).join('')}</div>` : ''}
      </aside>
      <div class="workbench-main">
        <div class="wb-toolbar">
          <div class="tabbar" role="tablist" aria-label="Workbench views">
            ${[['source', 'Source', 'code'], ['structure', 'Structure', 'list'], ['zones', 'Zones', 'database'], ['learn', 'Learn this config', 'book']].map(([id, label, iconName]) => `<button class="tab" role="tab" type="button" aria-selected="${activeTab === id}" data-tab="${id}">${icon(iconName, 15)} ${label}${id === 'zones' ? `<span class="tab-count">${model?.zones?.length || 0}</span>` : ''}</button>`).join('')}
          </div>
          <span class="tabbar-status" id="analysis-status">${analysis ? `Analyzed ${new Date(analysis.analyzedAt).toLocaleTimeString(undefined, { hourCycle: 'h23' })}` : 'Analyzing…'}</span>
        </div>
        <div class="tab-panel">${panelHtml()}</div>
      </div>
    </div>
    <div class="workbench-next">
      <a class="next-card" href="#/analyze"><span class="feature-icon">${icon('shield', 18)}</span><div><strong>Analyze the whole workspace</strong><span>Security, delegation, DNSSEC and zone hygiene with explanations.</span></div>${icon('arrow', 15)}</a>
      <a class="next-card" href="#/live"><span class="feature-icon">${icon('globe', 18)}</span><div><strong>Verify live DNS</strong><span>Compare expected records with Cloudflare and Google over DoH.</span></div>${icon('arrow', 15)}</a>
      <a class="next-card" href="#/workbench?export=1"><span class="feature-icon">${icon('package', 18)}</span><div><strong>Export without guessing</strong><span>ZIP bundle, hashes, validate.sh and dig verification plan.</span></div>${icon('arrow', 15)}</a>
    </div>`;
  }

  function paint() {
    const file = activeFile();
    parseNow();
    view.innerHTML = workspace.files.length ? shellHtml() : workspaceEmptyState('No files in this workspace', 'Add a named.conf or zone file, or import a fresh workspace.');
    updateStats();
    wireCopyButtons(view);
    wireShell();
    if (activeTab === 'source' && file) {
      editor = view.querySelector('#config-editor');
      lineNumbers = view.querySelector('#line-numbers');
      validationPanel = view.querySelector('#validation-panel');
      if (editor) {
        editor.value = file.content;
        updateEditorChrome();
        updateValidationPanel();
        editor.addEventListener('input', () => {
          selectedFileFromEditor();
          updateEditorChrome();
        });
        editor.addEventListener('scroll', () => {
          if (lineNumbers) lineNumbers.scrollTop = editor.scrollTop;
        });
        editor.addEventListener('keydown', (event) => {
          if (event.key === 'Tab') {
            event.preventDefault();
            const start = editor.selectionStart;
            const end = editor.selectionEnd;
            editor.setRangeText('    ', start, end, 'end');
            selectedFileFromEditor();
            updateEditorChrome();
          }
        });
      }
    }
    if (pendingLine && activeTab === 'source') {
      const lineToJump = pendingLine;
      setTimeout(() => jumpToLine(lineToJump), 60);
      pendingLine = null;
    }
    if (!exportHandled && query.get('export') === '1') {
      exportHandled = true;
      const [pathPart, queryPart = ''] = location.hash.split('?');
      const params = new URLSearchParams(queryPart);
      params.delete('export');
      const nextHash = `${pathPart}${params.toString() ? `?${params.toString()}` : ''}`;
      history.replaceState(null, '', nextHash || '#/workbench');
      openExportModal();
    }
  }

  function wireShell() {
    wireImportControls(view, {
      navigate: false,
      onImported: () => window.dispatchEvent(new Event('workbench:reload')),
    });
    view.querySelectorAll('[data-tab]').forEach((button) => button.addEventListener('click', () => setTab(button.dataset.tab)));
    view.querySelectorAll('[data-file-id]').forEach((button) => button.addEventListener('click', () => setFile(button.dataset.fileId)));
    view.querySelector('[data-add-file]')?.addEventListener('click', showAddFile);
    view.querySelector('[data-save-snapshot]')?.addEventListener('click', () => snapshot('Manual save', 'save'));
    view.querySelector('[data-export-bundle]')?.addEventListener('click', openExportModal);
    view.querySelector('[data-file-download]')?.addEventListener('click', () => {
      const file = activeFile();
      if (file) downloadWorkspaceFile(file);
    });
    view.querySelector('[data-file-rename]')?.addEventListener('click', showRenameFile);
    view.querySelector('[data-file-delete]')?.addEventListener('click', deleteFile);
    view.querySelector('[data-file-entry]')?.addEventListener('click', () => {
      const file = activeFile();
      if (!file) return;
      workspace.entry = file.path;
      saveWorkspaceNow();
      toast('Entry file updated.', 'ok');
      paint();
    });
    view.querySelectorAll('[data-goto-file]').forEach((button) => {
      button.addEventListener('click', () => {
        const file = fileByPath(workspace, button.dataset.gotoFile);
        if (file) setFile(file.id, Number(button.dataset.gotoLine) || 1);
      });
    });
    view.querySelectorAll('[data-goto-line]').forEach((button) => {
      button.addEventListener('click', () => jumpToLine(Number(button.dataset.gotoLine)));
    });
    wireZoneFilters();
  }

  function wireZoneFilters() {
    view.querySelectorAll('[data-zone-search]').forEach((input) => {
      input.addEventListener('input', () => applyZoneFilter(Number(input.dataset.zoneSearch)));
    });
    view.querySelectorAll('[data-zone-type]').forEach((select) => {
      select.addEventListener('change', () => applyZoneFilter(Number(select.dataset.zoneType)));
    });
  }

  function applyZoneFilter(index) {
    const search = (view.querySelector(`[data-zone-search="${index}"]`)?.value || '').toLowerCase();
    const type = view.querySelector(`[data-zone-type="${index}"]`)?.value || '';
    const rows = view.querySelectorAll(`#zone-${index} [data-record-row]`);
    let visible = 0;
    rows.forEach((row) => {
      const match = (!search || row.dataset.search.includes(search)) && (!type || row.dataset.recordType === type);
      row.hidden = !match;
      if (match) visible += 1;
    });
    const count = view.querySelector(`[data-zone-count="${index}"]`);
    if (count) count.textContent = `${formatNumber(visible)} record${visible === 1 ? '' : 's'}`;
  }

  function showAddFile() {
    const { dialog, close } = openModal({
      title: 'Add a file',
      lede: 'Use the path BIND sees in includes. Relative paths are resolved inside this workspace.',
      body: `<div class="form-grid">
        <label class="field span-2"><span>Path</span><input id="new-file-path" type="text" placeholder="zones/db.example.com" autocomplete="off"><small>Examples: named.conf.options, zones/db.example.com, keys/xfr.key</small></label>
        <label class="field span-2"><span>Content</span><textarea id="new-file-content" rows="12" spellcheck="false" placeholder="$ORIGIN example.com.&#10;$TTL 3600&#10;@ IN SOA …"></textarea></label>
      </div>`,
      actions: `<button class="btn btn-ghost" type="button" data-modal-close>Cancel</button><button class="btn btn-primary" type="button" id="create-file">${icon('plus', 15)} Create file</button>`,
    });
    dialog.querySelector('#create-file').addEventListener('click', () => {
      const path = dialog.querySelector('#new-file-path').value.trim();
      const content = dialog.querySelector('#new-file-content').value;
      if (!path) {
        toast('A path is required.', 'danger');
        return;
      }
      if (workspace.files.some((file) => file.path.toLowerCase() === path.toLowerCase())) {
        toast('A file with that path already exists.', 'danger');
        return;
      }
      const file = makeWorkspaceFile(path, content);
      workspace.files.push(file);
      if (!workspace.entry) workspace.entry = file.path;
      activeFileId = file.id;
      saveWorkspaceNow();
      parseNow();
      analyzeNow().then(() => { if (!disposed) { paint(); updateStats(); } });
      close();
      toast('File added.', 'ok');
    });
  }

  function showRenameFile() {
    const file = activeFile();
    if (!file) return;
    const { dialog, close } = openModal({
      title: 'Rename file',
      body: `<label class="field"><span>Path</span><input id="rename-path" type="text" value="${escapeHTML(file.path)}" autocomplete="off"><small>Update includes manually if this path is referenced elsewhere.</small></label>`,
      actions: `<button class="btn btn-ghost" type="button" data-modal-close>Cancel</button><button class="btn btn-primary" type="button" id="rename-file">${icon('save', 15)} Rename</button>`,
    });
    dialog.querySelector('#rename-file').addEventListener('click', () => {
      const path = dialog.querySelector('#rename-path').value.trim();
      if (!path) return;
      if (workspace.files.some((item) => item.id !== file.id && item.path.toLowerCase() === path.toLowerCase())) {
        toast('Another file already uses that path.', 'danger');
        return;
      }
      const oldPath = file.path;
      file.path = path;
      file.name = path.split('/').pop();
      file.kind = detectFileKind(path, file.content);
      if (workspace.entry === oldPath) workspace.entry = path;
      saveWorkspaceNow();
      parseNow();
      analyzeNow().then(() => { if (!disposed) { paint(); updateStats(); } });
      close();
      toast('File renamed. Check include references.', 'warn');
    });
  }

  async function deleteFile() {
    const file = activeFile();
    if (!file) return;
    const confirmed = await confirmDialog({
      title: 'Delete this file?',
      message: `Delete <code>${escapeHTML(file.path)}</code> from the workspace? This does not touch your disk; it only changes this local workspace. A snapshot is created before deletion.`,
      confirmLabel: 'Delete file',
    });
    if (!confirmed) return;
    snapshot('Before deleting a file', 'delete');
    workspace.files = workspace.files.filter((item) => item.id !== file.id);
    if (workspace.entry === file.path) workspace.entry = guessEntryFile(workspace.files) || null;
    activeFileId = workspace.files[0]?.id || null;
    saveWorkspaceNow();
    parseNow();
    await analyzeNow();
    if (!disposed) paint();
    toast('File removed from the workspace.', 'ok');
  }

  function openExportModal() {
    const { dialog, close } = openModal({
      title: 'Export a validated bundle',
      lede: 'Download every source file with its path, plus a manifest, validation script and live verification plan.',
      wide: true,
      body: `<div class="export-summary">
        <div class="export-stat"><strong>${workspace.files.length}</strong><span>source files</span></div>
        <div class="export-stat"><strong>${model?.zones?.length || 0}</strong><span>zones</span></div>
        <div class="export-stat"><strong>${formatNumber(model?.summary?.records || 0)}</strong><span>records</span></div>
        <div class="export-stat"><strong>${analysis?.score ?? '—'}</strong><span>analysis score</span></div>
      </div>
      <div class="export-grid">
        <div>
          <h3>Included source files</h3>
          <ul class="export-file-list">${workspace.files.map((file) => `<li>${icon(file.kind === 'zone' ? 'database' : 'file', 14)} <code>${escapeHTML(file.path)}</code><span>${formatBytes(file.size)}</span></li>`).join('')}</ul>
        </div>
        <div>
          <h3>Generated extras</h3>
          <ul class="export-file-list">
            <li>${icon('file', 14)} <code>BIND-WORKBENCH-MANIFEST.json</code><span>SHA-256 + summary</span></li>
            <li>${icon('terminal', 14)} <code>validate.sh</code><span>named-checkconf/zone</span></li>
            <li>${icon('book', 14)} <code>VALIDATE.md</code><span>procedure</span></li>
            <li>${icon('globe', 14)} <code>VERIFY.md</code><span>dig plan</span></li>
            <li>${icon('package', 14)} <code>bind-workbench-workspace.json</code><span>re-import</span></li>
          </ul>
          <div class="callout warn">${icon('warning', 18)}<div><strong>Review before deployment</strong><p>The bundle is a source export, not a deployment tool. Absolute paths, permissions, SELinux labels, journals and live delegation must be checked separately.</p></div></div>
        </div>
      </div>
      <label class="checkbox-field"><input type="checkbox" id="export-workspace-json" checked><span>Include a workspace JSON file for re-import</span><small>It may contain TSIG secrets found in the source files. Store it accordingly.</small></label>
      <label class="checkbox-field"><input type="checkbox" id="export-validation" checked><span>Include validate.sh, VALIDATE.md and VERIFY.md</span></label>
      <div class="modal-privacy">${icon('lock', 15)}<p>The export is generated in this browser. Nothing is uploaded. The downloaded ZIP contains your configuration data in plaintext.</p></div>`,
      actions: `<button class="btn btn-ghost" type="button" data-modal-close>Cancel</button><button class="btn" type="button" id="export-json">${icon('download', 15)} Workspace JSON</button><button class="btn btn-primary" type="button" id="export-zip">${icon('package', 15)} Download ZIP</button>`,
    });
    dialog.querySelector('#export-json').addEventListener('click', () => {
      downloadWorkspaceJson(workspace);
      toast('Workspace JSON downloaded.', 'ok');
    });
    dialog.querySelector('#export-zip').addEventListener('click', async () => {
      const button = dialog.querySelector('#export-zip');
      const original = button.innerHTML;
      button.disabled = true;
      button.innerHTML = `<span class="spinner"></span> Building bundle…`;
      try {
        const bundle = await downloadWorkspaceZip(workspace, model, {
          includeWorkspaceJson: dialog.querySelector('#export-workspace-json').checked,
          includeValidation: dialog.querySelector('#export-validation').checked,
          analysisSummary: analysis ? { score: analysis.score, counts: analysis.counts, findings: analysis.total } : null,
        });
        saveSnapshot(workspace, { label: 'Before export', source: 'export' });
        toast(`Downloaded ${bundle.files.length} files as ${bundle.filename}.`, 'ok');
        close();
      } catch (error) {
        toast(error?.message || 'Could not build the export bundle.', 'danger');
        button.disabled = false;
        button.innerHTML = original;
      }
    });
  }

  // Initial parse and analysis before the first paint.
  selectInitialFile();
  parseNow();
  try {
    await analyzeNow();
  } catch (error) {
    console.warn('Initial analysis failed', error);
  }
  if (disposed) return null;
  paint();

  const saveHandler = () => snapshot('Keyboard save', 'save');
  window.addEventListener('workbench:save', saveHandler);
  cleanups.push(() => window.removeEventListener('workbench:save', saveHandler));
  const pagehide = () => {
    if (editor && activeTab === 'source') selectedFileFromEditor();
    saveWorkspaceNow();
  };
  window.addEventListener('pagehide', pagehide);
  cleanups.push(() => window.removeEventListener('pagehide', pagehide));
  cleanups.push(() => {
    disposed = true;
    clearTimeout(parseTimer);
    clearTimeout(analysisTimer);
    clearTimeout(saveTimer);
    if (editor && activeTab === 'source') selectedFileFromEditor();
    saveWorkspaceNow();
  });

  return () => {
    for (const cleanup of cleanups) {
      try {
        cleanup();
      } catch {
        /* ignore */
      }
    }
  };
}

function workspaceEmptyState(title = 'No workspace loaded', body = 'Import named.conf, includes and zone files, or start from an example. Everything stays in this browser.') {
  return `<div class="page-head">
    <div class="page-head-copy"><span class="eyebrow">Workbench</span><h1>${escapeHTML(title)}</h1><p class="page-lede">${escapeHTML(body)}</p></div>
    <div class="page-actions"><button class="btn btn-primary" type="button" data-import-files>${icon('upload', 16)} Import files</button><button class="btn" type="button" data-import-folder>${icon('folder', 16)} Import folder</button><a class="btn btn-ghost" href="#/">Examples</a></div>
  </div>
  <div class="start-panel">
    <div class="start-copy"><span class="eyebrow">Start here</span><h2>Drop a folder or a ZIP</h2><p>Folder import preserves paths so includes and zone files resolve correctly. A single named.conf works too; unresolved includes are reported.</p><div class="start-actions"><button class="btn btn-primary" type="button" data-import-files>${icon('upload', 16)} Choose files</button><button class="btn" type="button" data-import-folder>${icon('folder', 16)} Choose folder</button></div><p class="muted-note">${icon('info', 14)} Files are read with the browser File API. Nothing is uploaded.</p></div>
    <div class="dropzone" data-dropzone tabindex="0" role="button" aria-label="Drop BIND configuration files here"><div class="dropzone-icon">${icon('upload', 24)}</div><strong>Drop files here</strong><span>named.conf, zones, includes, ZIP</span><small>Local-first</small></div>
    <div data-upload-gate></div>
  </div>`;
}

export { workspaceEmptyState };
