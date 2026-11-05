/* Analysis page: explainable findings and best-practice checklist. */

import { analyzeWorkspace } from '../dns/analyzer.js';
import { parseWorkspace } from '../dns/workspace.js';
import { getCurrentWorkspace } from '../storage.js';
import { icon, pill, scoreGauge, toast, wireCopyButtons } from '../ui.js';
import { escapeHTML, formatDateTime, formatNumber } from '../utils.js';
import { downloadText } from '../utils.js';
import { wireImportControls } from './import-ui.js';

const SEVERITIES = ['error', 'warning', 'recommendation', 'info'];

export async function renderAnalyze(view, query) {
  const workspace = getCurrentWorkspace();
  if (!workspace) {
    view.innerHTML = `<div class="page-head"><div class="page-head-copy"><span class="eyebrow">Analyze</span><h1>No workspace to analyze</h1><p class="page-lede">Import named.conf and zone files first. Analysis runs locally and links every finding to the exact file and line.</p></div><div class="page-actions"><button class="btn btn-primary" type="button" data-import-files>${icon('upload', 16)} Import files</button><button class="btn" type="button" data-import-folder>${icon('folder', 16)} Import folder</button></div></div>
    <div class="start-panel"><div class="start-copy"><h2>Bring the whole include tree</h2><p>For delegation and DNSSEC checks, import the parent and child zones together. Missing files are reported, not guessed.</p></div><div class="dropzone" data-dropzone tabindex="0" role="button"><div class="dropzone-icon">${icon('upload', 24)}</div><strong>Drop files or a folder</strong><span>named.conf, includes, zones, ZIP</span></div></div>`;
    wireImportControls(view, { navigate: true });
    return null;
  }

  const model = parseWorkspace(workspace);
  const analysis = await analyzeWorkspace(workspace, model);
  const initialSeverity = query.get('severity') || 'all';
  let activeTab = query.get('tab') === 'practices' ? 'practices' : 'findings';
  let severity = SEVERITIES.includes(initialSeverity) ? initialSeverity : 'all';
  let category = 'all';
  let search = '';

  const countPill = (severityName, label) => {
    const count = analysis.counts[severityName] || 0;
    return `<button class="score-count ${severity === severityName ? 'active' : ''}" type="button" data-severity="${severityName}"><strong>${formatNumber(count)}</strong><span>${escapeHTML(label)}</span></button>`;
  };

  const categoryOptions = ['all', ...Array.from(new Set(analysis.findings.map((finding) => finding.category))).sort()];

  view.innerHTML = `<div class="page-head">
    <div class="page-head-copy">
      <span class="eyebrow">Analyze · ${escapeHTML(workspace.name)}</span>
      <h1>What will bite you?</h1>
      <p class="page-lede">Every finding has a line reference, a reason and a concrete recommendation. This is a deep static review, not a substitute for <code>named-checkconf</code> and <code>named-checkzone</code>.</p>
      <div class="meta-strip">${pill(`${model.summary.files} files`, 'neutral', 'file')}${pill(`${model.summary.zones} zones`, 'accent', 'database')}${pill(`${formatNumber(model.summary.records)} records`, 'neutral', 'list')}${pill(`analyzed ${formatDateTime(analysis.analyzedAt)}`, 'neutral', 'clock')}</div>
    </div>
    <div class="page-actions">
      <a class="btn" href="#/workbench">${icon('code', 16)} Workbench</a>
      <a class="btn" href="#/compare">${icon('diff', 16)} Compare</a>
      <a class="btn btn-primary" href="#/workbench?export=1">${icon('package', 16)} Export bundle</a>
    </div>
  </div>

  <section class="score-panel">
    ${scoreGauge(analysis.score, 'score')}
    <div class="score-copy">
      <span class="eyebrow">Grade ${escapeHTML(analysis.grade)}</span>
      <h2>${analysis.total ? `${formatNumber(analysis.total)} things to review` : 'No findings — a clean static pass'}</h2>
      <p>Score starts at 100 and subtracts weighted errors, warnings and recommendations. It is a review aid, not a security certification. A perfect score still does not prove live DNS, delegation, permissions or DNSSEC chain correctness.</p>
      <div class="score-counts">
        <button class="score-count ${severity === 'all' ? 'active' : ''}" type="button" data-severity="all"><strong>${formatNumber(analysis.total)}</strong><span>all</span></button>
        ${countPill('error', 'errors')}
        ${countPill('warning', 'warnings')}
        ${countPill('recommendation', 'advice')}
        ${countPill('info', 'notes')}
      </div>
    </div>
    <div class="score-side">
      <div class="fact">${icon('shield', 18)}<div><strong>${formatNumber(analysis.findings.filter((finding) => finding.category === 'DNSSEC').length)} DNSSEC findings</strong><span>keys, DS, signatures and policy</span></div></div>
      <div class="fact">${icon('network', 18)}<div><strong>${formatNumber(analysis.findings.filter((finding) => ['Delegation', 'Transfers', 'Recursion'].includes(finding.category)).length)} topology findings</strong><span>delegation, recursion and transfers</span></div></div>
    </div>
  </section>

  <div class="tabbar analyze-tabs" role="tablist">
    <button class="tab" type="button" role="tab" aria-selected="${activeTab === 'findings'}" data-analysis-tab="findings">${icon('list', 15)} Findings <span class="tab-count">${analysis.total}</span></button>
    <button class="tab" type="button" role="tab" aria-selected="${activeTab === 'practices'}" data-analysis-tab="practices">${icon('check', 15)} Best practices <span class="tab-count">${analysis.checklist.length}</span></button>
  </div>

  <section class="analysis-panel" data-panel="findings" ${activeTab === 'findings' ? '' : 'hidden'}>
    <div class="filterbar">
      <div class="filter-chips">${['all', ...SEVERITIES].map((name) => `<button class="chip ${severity === name ? 'active' : ''}" type="button" data-severity="${name}">${name === 'all' ? 'All' : name[0].toUpperCase() + name.slice(1)}${name === 'all' ? '' : ` ${analysis.counts[name] || 0}`}</button>`).join('')}</div>
      <select class="select" id="filter-category" aria-label="Filter by category"><option value="all">All categories</option>${categoryOptions.filter((item) => item !== 'all').map((item) => `<option value="${escapeHTML(item)}">${escapeHTML(item)}</option>`).join('')}</select>
      <div class="search-field">${icon('search', 15)}<input type="search" id="finding-search" placeholder="Search findings…" aria-label="Search findings"></div>
      <span class="filter-result" id="finding-count">${formatNumber(analysis.total)} findings</span>
      <button class="btn btn-sm btn-ghost" type="button" id="download-findings">${icon('download', 14)} JSON</button>
    </div>
    <div class="finding-list" id="finding-list"></div>
  </section>

  <section class="analysis-panel" data-panel="practices" ${activeTab === 'practices' ? '' : 'hidden'}>
    <div class="callout info">${icon('info', 18)}<div><strong>How to use the checklist</strong><p>Pass means the static evidence supports the practice. Review means the evidence is missing, ambiguous or environment-dependent. Fail means a concrete rule is broken. Each item links to the reasoning.</p></div></div>
    <div class="checklist">${renderChecklist(analysis.checklist)}</div>
  </section>

  <div class="callout warn analyze-disclaimer">${icon('warning', 18)}<div><strong>Important limits</strong><p>This analyzer cannot run BIND, resolve live delegations, inspect file permissions, verify TSIG secrets, or prove that a DNSSEC chain is intact. Use <code>named-checkconf -z</code>, <code>named-checkzone</code>, <code>delv</code>/<code>dig</code> and the Live DNS page for the external truth.</p></div></div>
  <div class="link-row"><a class="btn" href="#/learn/hardening">${icon('book', 15)} Hardening guide</a><a class="btn" href="#/learn/dnssec-chain">${icon('shield', 15)} DNSSEC chain</a><a class="btn" href="#/learn/change-workflow">${icon('route', 15)} Safe change workflow</a></div>
  `;

  const list = view.querySelector('#finding-list');
  const countLabel = view.querySelector('#finding-count');

  function applyFilters() {
    const filtered = analysis.findings.filter((finding) => {
      if (severity !== 'all' && finding.severity !== severity) return false;
      if (category !== 'all' && finding.category !== category) return false;
      if (search) {
        const haystack = `${finding.title} ${finding.message} ${finding.why} ${finding.recommendation} ${finding.file} ${finding.zone} ${finding.category}`.toLowerCase();
        if (!haystack.includes(search.toLowerCase())) return false;
      }
      return true;
    });
    countLabel.textContent = `${formatNumber(filtered.length)} finding${filtered.length === 1 ? '' : 's'}`;
    list.innerHTML = filtered.length
      ? filtered.map(renderFinding).join('')
      : `<div class="empty-filter">${icon('check', 18)} No findings match this filter.</div>`;
    wireFindingLinks();
    wireCopyButtons(list);
  }

  function wireFindingLinks() {
    view.querySelectorAll('[data-finding-file]').forEach((button) => {
      button.addEventListener('click', () => {
        const file = button.dataset.findingFile;
        const line = button.dataset.findingLine || '1';
        location.hash = `#/workbench?file=${encodeURIComponent(file)}&line=${encodeURIComponent(line)}`;
      });
    });
  }

  view.querySelectorAll('[data-analysis-tab]').forEach((button) => {
    button.addEventListener('click', () => {
      activeTab = button.dataset.analysisTab;
      view.querySelectorAll('[data-analysis-tab]').forEach((item) => item.setAttribute('aria-selected', String(item === button)));
      view.querySelectorAll('[data-panel]').forEach((panel) => {
        panel.hidden = panel.dataset.panel !== activeTab;
      });
    });
  });
  view.querySelectorAll('[data-severity]').forEach((button) => {
    button.addEventListener('click', () => {
      severity = button.dataset.severity;
      view.querySelectorAll('[data-severity]').forEach((item) => item.classList.toggle('active', item.dataset.severity === severity));
      applyFilters();
    });
  });
  view.querySelector('#filter-category')?.addEventListener('change', (event) => {
    category = event.target.value;
    applyFilters();
  });
  view.querySelector('#finding-search')?.addEventListener('input', (event) => {
    search = event.target.value;
    applyFilters();
  });
  view.querySelector('#download-findings')?.addEventListener('click', () => {
    const payload = {
      generatedAt: new Date().toISOString(),
      workspace: workspace.name,
      score: analysis.score,
      grade: analysis.grade,
      counts: analysis.counts,
      findings: analysis.findings,
    };
    downloadText('bind-workbench-findings.json', JSON.stringify(payload, null, 2), 'application/json');
    toast('Findings JSON downloaded.', 'ok');
  });

  applyFilters();
  return null;
}

function renderFinding(finding) {
  const learnHref = `#/learn/${encodeURIComponent(finding.learn || 'hardening')}`;
  return `<article class="finding-card" data-severity="${finding.severity}">
    <div class="finding-top">
      <span class="pill ${finding.severity === 'error' ? 'danger' : finding.severity === 'warning' ? 'warn' : finding.severity === 'recommendation' ? 'accent' : 'neutral'}">${escapeHTML(finding.severity)}</span>
      <span class="finding-category">${escapeHTML(finding.category)}</span>
      ${finding.zone ? `<span class="finding-section">${escapeHTML(finding.zone)}</span>` : ''}
      ${finding.file ? `<button class="line-link" type="button" data-finding-file="${escapeHTML(finding.file)}" data-finding-line="${finding.line || 1}">${icon('code', 13)} ${escapeHTML(finding.file)}${finding.line ? `:${finding.line}` : ''}</button>` : ''}
    </div>
    <h3>${escapeHTML(finding.title)}</h3>
    <p>${escapeHTML(finding.message)}</p>
    <details class="finding-more">
      <summary>Why it matters and what to do</summary>
      <div class="finding-more-body">
        ${finding.why ? `<div><h4>Why</h4><p>${escapeHTML(finding.why)}</p></div>` : ''}
        ${finding.recommendation ? `<div class="fix-box"><h4>${icon('check', 13)} Recommendation</h4><p>${escapeHTML(finding.recommendation)}</p></div>` : ''}
        ${finding.details?.length ? `<div><h4>Details</h4><ul>${finding.details.map((item) => `<li>${escapeHTML(item)}</li>`).join('')}</ul></div>` : ''}
        <div class="explain-links"><a class="learn-link" href="${learnHref}">${icon('book', 14)} Learn the concept</a></div>
      </div>
    </details>
  </article>`;
}

function renderChecklist(items) {
  const categories = new Map();
  for (const item of items) {
    if (!categories.has(item.category)) categories.set(item.category, []);
    categories.get(item.category).push(item);
  }
  return Array.from(categories.entries()).map(([category, list]) => `<div class="checklist-group"><h3>${escapeHTML(category)}</h3>${list.map((item) => `<div class="check-item">
    <div class="check-icon ${item.status === 'pass' ? 'ok' : item.status === 'fail' ? 'danger' : 'warn'}">${icon(item.status === 'pass' ? 'check' : item.status === 'fail' ? 'error' : 'warning', 15)}</div>
    <div class="check-copy"><div class="check-title"><strong>${escapeHTML(item.title)}</strong><span class="pill ${item.status === 'pass' ? 'ok' : item.status === 'fail' ? 'danger' : 'warn'}">${escapeHTML(item.status)}</span></div><p>${escapeHTML(item.detail)}</p><a class="learn-link" href="#/learn/${encodeURIComponent(item.learn || 'hardening')}">${icon('book', 13)} Why this matters</a></div>
  </div>`).join('')}</div>`).join('');
}
