/* Zone explorer: records, SOA/NS, DNSSEC inventory and per-zone findings. */

import { analyzeWorkspace } from '../dns/analyzer.js';
import { parseWorkspace } from '../dns/workspace.js';
import { zoneDnssecInventory } from '../dns/dnssec.js';
import { getCurrentWorkspace } from '../storage.js';
import { recordDoc } from '../data/records.js';
import { icon, pill, wireCopyButtons } from '../ui.js';
import { formatTTL } from '../dns/syntax.js';
import { escapeHTML, formatNumber } from '../utils.js';
import { wireImportControls } from './import-ui.js';

export async function renderZones(view, param, query) {
  const workspace = getCurrentWorkspace();
  if (!workspace) {
    view.innerHTML = `<div class="page-head"><div class="page-head-copy"><span class="eyebrow">Zones</span><h1>No zones loaded</h1><p class="page-lede">Import named.conf and its zone files, or drop a standalone master file. A zone-only workspace is parsed with an inferred origin.</p></div><div class="page-actions"><button class="btn btn-primary" type="button" data-import-files>${icon('upload', 16)} Import files</button><button class="btn" type="button" data-import-folder>${icon('folder', 16)} Import folder</button></div></div><div class="start-panel"><div class="start-copy"><h2>Bring the whole zone set</h2><p>Parent and child zones together let the analyzer check delegation NS consistency, glue and DS ↔ DNSKEY matching.</p></div><div class="dropzone" data-dropzone tabindex="0" role="button"><div class="dropzone-icon">${icon('database', 24)}</div><strong>Drop zones or a folder</strong><span>zone files, named.conf, ZIP</span></div></div>`;
    wireImportControls(view, { navigate: true });
    return null;
  }

  const model = parseWorkspace(workspace);
  const analysis = await analyzeWorkspace(workspace, model);
  const selectedZone = query.get('zone') || param || null;
  const zones = model.zones || [];
  const signed = zones.filter((zone) => zoneDnssecInventory(zone.parsed).signed).length;
  const withFile = zones.filter((zone) => zone.filePath).length;
  const records = zones.reduce((total, zone) => total + (zone.parsed?.records?.length || 0), 0);
  const zoneNames = new Set((analysis.findings || []).map((finding) => finding.zone).filter(Boolean)).size;

  view.innerHTML = `<div class="page-head">
    <div class="page-head-copy"><span class="eyebrow">Zones · ${escapeHTML(workspace.name)}</span><h1>Every record, in context</h1><p class="page-lede">Browse parsed master files, inspect SOA and NS data, filter records and follow a line back to the source. DNSSEC state is computed from the keys, signatures and denial records actually present.</p><div class="meta-strip">${pill(`${zones.length} zones`, 'accent', 'database')}${pill(`${formatNumber(records)} records`, 'neutral', 'list')}${pill(`${signed} signed`, signed ? 'ok' : 'neutral', 'shield')}${pill(`${withFile} files resolved`, withFile === zones.length ? 'ok' : 'warn', 'file')}</div></div>
    <div class="page-actions"><a class="btn" href="#/workbench">${icon('code', 16)} Workbench</a><a class="btn" href="#/analyze">${icon('shield', 16)} Analyze</a><a class="btn btn-primary" href="#/live?tab=verify">${icon('globe', 16)} Verify live</a></div>
  </div>

  ${zones.length ? `<div class="zone-nav">${zones.map((zone, index) => `<a class="zone-nav-item ${selectedZone === zone.name ? 'active' : ''}" href="#/zones?zone=${encodeURIComponent(zone.name)}"><span>${escapeHTML(zone.name)}</span><small>${zone.parsed?.records?.length || 0} records${zone.view ? ` · ${escapeHTML(zone.view)}` : ''}</small></a>`).join('')}</div>` : ''}

  <div class="zone-summary-strip">
    ${pill(`${zones.length} zone${zones.length === 1 ? '' : 's'}`, 'accent', 'database')}
    ${pill(`${zoneNames} with analyzer notes`, zoneNames ? 'warn' : 'ok', 'warning')}
    ${pill(`${analysis.counts.error} errors`, analysis.counts.error ? 'danger' : 'ok', 'error')}
    ${pill(`${analysis.counts.warning} warnings`, analysis.counts.warning ? 'warn' : 'ok', 'warning')}
    <span class="muted-note">${icon('info', 14)} Records are canonicalised for comparison; the source line link is exact.</span>
  </div>

  <div class="zone-list">${zones.length ? zones.map((zone, index) => renderZone(zone, index, selectedZone, analysis)).join('') : `<div class="empty-panel"><h2>No zones found</h2><p>Add a zone declaration or import a master file.</p><a class="btn btn-primary" href="#/workbench">Open workbench</a></div>`}</div>
  <div class="callout info zone-disclaimer">${icon('info', 18)}<div><strong>Verified statically</strong><p>The table is built from the imported files. BIND may serve different data because of a journal, inline signing, a secondary transfer or a view. Always compare the deployed state and run <code>named-checkzone</code> on the exact file.</p></div></div>
  `;

  wireCopyButtons(view);
  wireZoneInteractions(view, zones);
  return null;
}

function renderZone(zone, index, selectedZone, analysis) {
  const records = zone.parsed?.records || [];
  const inventory = zoneDnssecInventory(zone.parsed);
  const findings = (analysis.findings || []).filter((finding) => finding.zone === zone.name || finding.file === zone.filePath);
  const errors = findings.filter((finding) => finding.severity === 'error');
  const warnings = findings.filter((finding) => finding.severity === 'warning');
  const types = Array.from(new Set(records.map((record) => record.type))).sort();
  const open = selectedZone ? selectedZone === zone.name : index === 0;
  const renderedRecords = records.slice(0, 2000);
  const rows = renderedRecords.map((record) => {
    const search = `${record.owner} ${record.type} ${record.rdata} ${record.ttl || ''} ${record.class}`.toLowerCase();
    return `<tr data-record-row data-search="${escapeHTML(search)}" data-record-type="${escapeHTML(record.type)}">
      <td class="row-line"><button class="button-like" type="button" data-goto-file="${escapeHTML(record.file)}" data-goto-line="${record.line}">${record.line}</button></td>
      <td><code>${escapeHTML(record.owner)}</code></td>
      <td class="mono">${record.ttl === null ? '<span class="text-warn">—</span>' : escapeHTML(formatTTL(record.ttl))}</td>
      <td><span class="record-type">${escapeHTML(record.type)}</span></td>
      <td class="record-data"><code>${escapeHTML(record.rdata)}</code></td>
      <td>${recordDoc(record.type) ? `<a class="learn-link" href="#/reference?tab=records&q=${encodeURIComponent(record.type)}" title="${escapeHTML(recordDoc(record.type).summary)}">${icon('book', 13)}</a>` : ''}</td>
    </tr>`;
  }).join('');
  const soa = zone.parsed?.soa;
  const ns = records.filter((record) => record.type === 'NS' && record.owner === zone.name);
  return `<details class="zone-card zone-details" id="zone-${index}" ${open ? 'open' : ''}>
    <summary class="zone-head">
      <div class="zone-title">${icon('database', 20)}<div><h2>${escapeHTML(zone.name)}</h2><p>${escapeHTML(zone.type || 'unknown type')}${zone.view ? ` · view ${escapeHTML(zone.view)}` : ''}${zone.synthetic ? ' · standalone file' : ''}${zone.filePath ? ` · ${escapeHTML(zone.filePath)}` : ' · file not in workspace'}</p></div></div>
      <div class="zone-metrics">${pill(`${records.length} records`, 'neutral', 'list')}${pill(soa ? `serial ${soa.data.serial}` : 'no SOA', soa ? 'accent' : 'danger', 'clock')}${pill(`${inventory.keys.length} DNSKEY`, inventory.keys.length ? 'ok' : 'neutral', 'key')}${pill(`${inventory.rrsigs.length} RRSIG`, inventory.rrsigs.length ? 'ok' : 'neutral', 'shield')}${errors.length ? pill(`${errors.length} errors`, 'danger', 'error') : ''}${warnings.length ? pill(`${warnings.length} warnings`, 'warn', 'warning') : ''}</div>
      <span class="chev">${icon('chevron', 17)}</span>
    </summary>
    <div class="zone-body">
      <div class="zone-facts">
        <div class="fact">${icon('clock', 17)}<div><strong>SOA</strong><span>${soa ? `serial ${escapeHTML(soa.data.serial)} · refresh ${escapeHTML(formatTTL(soa.data.refresh))} · retry ${escapeHTML(formatTTL(soa.data.retry))} · expire ${escapeHTML(formatTTL(soa.data.expire))} · min ${escapeHTML(formatTTL(soa.data.minimum))}` : 'No SOA parsed'}</span></div></div>
        <div class="fact">${icon('network', 17)}<div><strong>Apex NS</strong><span>${ns.length ? ns.map((record) => escapeHTML(record.data.target)).join(' · ') : 'No apex NS parsed'}</span></div></div>
        <div class="fact">${icon('shield', 17)}<div><strong>DNSSEC</strong><span>${inventory.signed ? `signed · ${inventory.keys.length} keys · denial ${escapeHTML(inventory.denial)}` : 'no RRSIG records in the imported file'}${inventory.ds.length ? ` · ${inventory.ds.length} DS/CDS` : ''}</span></div></div>
      </div>
      ${findings.length ? `<div class="zone-findings">${findings.slice(0, 10).map((finding) => `<div class="zone-finding ${finding.severity}"><span class="sev-dot ${finding.severity}"></span><div><strong>${escapeHTML(finding.title)}</strong><span>${escapeHTML(finding.message)}</span></div>${finding.file ? `<button class="button-like" type="button" data-goto-file="${escapeHTML(finding.file)}" data-goto-line="${finding.line || 1}">line ${finding.line || 1}</button>` : ''}</div>`).join('')}</div>` : `<div class="zone-ok">${icon('check', 15)} No analyzer findings for this zone.</div>`}
      <div class="zone-actions zone-actions-bottom">
        ${zone.filePath ? `<button class="btn btn-sm btn-ghost" type="button" data-goto-file="${escapeHTML(zone.filePath)}" data-goto-line="1">${icon('code', 14)} Open source</button>` : ''}
        <a class="btn btn-sm" href="#/live?tab=verify&zone=${encodeURIComponent(zone.name)}">${icon('globe', 14)} Verify live</a>
        ${zone.filePath ? `<button class="btn btn-sm btn-ghost" type="button" data-copy="named-checkzone '${escapeHTML(zone.name)}' '${escapeHTML(zone.filePath)}'">${icon('terminal', 14)} named-checkzone</button>` : ''}
      </div>
      <div class="zone-records-toolbar">
        <div class="search-field">${icon('search', 15)}<input type="search" placeholder="Filter owner, type or RDATA…" data-zone-search="${index}" aria-label="Filter records"></div>
        <select class="select" data-zone-type="${index}" aria-label="Filter by record type"><option value="">All types</option>${types.map((type) => `<option value="${escapeHTML(type)}">${escapeHTML(type)}</option>`).join('')}</select>
        <span class="filter-result" data-zone-count="${index}">${formatNumber(records.length)} records</span>
      </div>
      <div class="table-scroll"><table class="record-table"><thead><tr><th>Line</th><th>Owner</th><th>TTL</th><th>Type</th><th>RDATA</th><th></th></tr></thead><tbody>${rows || '<tr><td colspan="6" class="muted">No records parsed for this zone.</td></tr>'}</tbody></table></div>
      <div class="zone-foot"><span>${icon('file', 13)} ${escapeHTML(zone.filePath || 'file not resolved')}</span><span>${inventory.denial === 'none' ? 'No denial records' : `Denial: ${escapeHTML(inventory.denial)}`}</span>${records.length > renderedRecords.length ? `<span>Showing first ${formatNumber(renderedRecords.length)} of ${formatNumber(records.length)} records</span>` : ''}</div>
    </div>
  </details>`;
}

function wireZoneInteractions(view, zones) {
  view.querySelectorAll('[data-goto-file]').forEach((button) => {
    button.addEventListener('click', () => {
      const file = button.dataset.gotoFile;
      const line = button.dataset.gotoLine || '1';
      location.hash = `#/workbench?file=${encodeURIComponent(file)}&line=${encodeURIComponent(line)}`;
    });
  });
  view.querySelectorAll('[data-zone-search]').forEach((input) => {
    input.addEventListener('input', () => applyZoneFilter(Number(input.dataset.zoneSearch)));
  });
  view.querySelectorAll('[data-zone-type]').forEach((select) => {
    select.addEventListener('change', () => applyZoneFilter(Number(select.dataset.zoneType)));
  });
  void zones;
}

function applyZoneFilter(index) {
  const search = (document.querySelector(`[data-zone-search="${index}"]`)?.value || '').toLowerCase();
  const type = document.querySelector(`[data-zone-type="${index}"]`)?.value || '';
  const rows = document.querySelectorAll(`#zone-${index} [data-record-row]`);
  let visible = 0;
  rows.forEach((row) => {
    const match = (!search || row.dataset.search.includes(search)) && (!type || row.dataset.recordType === type);
    row.hidden = !match;
    if (match) visible += 1;
  });
  const count = document.querySelector(`[data-zone-count="${index}"]`);
  if (count) count.textContent = `${formatNumber(visible)} record${visible === 1 ? '' : 's'}`;
}
