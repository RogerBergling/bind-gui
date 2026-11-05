/* Reference encyclopedia for named.conf directives and DNS record types. */

import { DIRECTIVE_DOCS, DIRECTIVE_CATEGORIES } from '../data/directives.js';
import { RECORD_DOCS, RECORD_CATEGORIES } from '../data/records.js';
import { icon, pill, wireCopyButtons } from '../ui.js';
import { escapeHTML, formatNumber } from '../utils.js';

export function renderReference(view, query) {
  let tab = query.get('tab') === 'records' ? 'records' : 'directives';
  let searchTerm = query.get('q') || '';
  let category = 'all';

  view.innerHTML = `<div class="page-head">
    <div class="page-head-copy"><span class="eyebrow">Reference</span><h1>The full syntax, not a teaser</h1><p class="page-lede">${DIRECTIVE_DOCS.length} named.conf statements and ${RECORD_DOCS.length} DNS record types with context, syntax, security notes, gotchas and links into the guides. Entries are version-aware where BIND behaviour differs.</p><div class="meta-strip">${pill(`${DIRECTIVE_DOCS.length} directives`, 'accent', 'file')}${pill(`${RECORD_DOCS.length} records`, 'neutral', 'database')}${pill('searchable', 'neutral', 'search')}</div></div>
    <div class="page-actions"><a class="btn" href="#/glossary">${icon('book', 16)} Glossary</a><a class="btn" href="#/learn">${icon('list', 16)} Learning guides</a></div>
  </div>
  <div class="tabbar" role="tablist">
    <button class="tab" type="button" role="tab" data-ref-tab="directives" aria-selected="${tab === 'directives'}">${icon('file', 15)} named.conf directives <span class="tab-count">${DIRECTIVE_DOCS.length}</span></button>
    <button class="tab" type="button" role="tab" data-ref-tab="records" aria-selected="${tab === 'records'}">${icon('database', 15)} DNS record types <span class="tab-count">${RECORD_DOCS.length}</span></button>
  </div>
  <div class="filterbar">
    <div class="search-field">${icon('search', 15)}<input type="search" id="ref-search" value="${escapeHTML(searchTerm)}" placeholder="Search syntax, names, categories…" aria-label="Search reference"></div>
    <select class="select" id="ref-category" aria-label="Filter category"><option value="all">All categories</option></select>
    <span class="filter-result" id="ref-count"></span>
  </div>
  <section data-ref-panel="directives" ${tab === 'directives' ? '' : 'hidden'}>
    <div class="reference-list" id="directive-list"></div>
  </section>
  <section data-ref-panel="records" ${tab === 'records' ? '' : 'hidden'}>
    <div class="reference-list" id="record-list"></div>
  </section>
  <div class="callout warn">${icon('warning', 18)}<div><strong>Version awareness</strong><p>BIND changes syntax across branches. Treat this reference as a study aid, then verify against the ARM and <code>named-checkconf</code> for the exact BIND version you deploy. Entries marked obsolete should not be copied into new configurations.</p></div></div>
  `;

  const search = view.querySelector('#ref-search');
  const categorySelect = view.querySelector('#ref-category');
  const count = view.querySelector('#ref-count');
  const directiveList = view.querySelector('#directive-list');
  const recordList = view.querySelector('#record-list');

  function updateCategories() {
    const categories = tab === 'directives' ? DIRECTIVE_CATEGORIES.map((item) => item.name) : RECORD_CATEGORIES;
    categorySelect.innerHTML = `<option value="all">All categories</option>${categories.map((name) => `<option value="${escapeHTML(name)}">${escapeHTML(name)}</option>`).join('')}`;
    category = 'all';
  }

  function directiveCategory(doc) {
    const entry = DIRECTIVE_CATEGORIES.find((item) => item.keywords.some((keyword) => doc.keyword.toLowerCase().includes(keyword) || doc.id.toLowerCase().includes(keyword)));
    return entry?.name || 'Other';
  }

  function paint() {
    const needle = searchTerm.toLowerCase().trim();
    if (tab === 'directives') {
      const docs = DIRECTIVE_DOCS.filter((doc) => {
        if (category !== 'all' && directiveCategory(doc) !== category) return false;
        if (!needle) return true;
        return `${doc.keyword} ${doc.name} ${doc.summary} ${doc.what} ${doc.context} ${doc.syntax} ${doc.security || ''}`.toLowerCase().includes(needle);
      });
      count.textContent = `${formatNumber(docs.length)} directive${docs.length === 1 ? '' : 's'}`;
      directiveList.innerHTML = docs.length ? docs.map((doc) => `<article class="reference-card" id="ref-${escapeHTML(doc.id)}">
        <div class="reference-head"><div><span class="eyebrow">${escapeHTML(directiveCategory(doc))}</span><h2><code>${escapeHTML(doc.keyword)}</code> <span>${escapeHTML(doc.name)}</span></h2></div><div class="meta-strip">${pill(doc.context, 'neutral', 'layers')}</div></div>
        <p>${escapeHTML(doc.summary)}</p>
        <div class="syntax-box"><span>syntax</span><code>${escapeHTML(doc.syntax)}</code><button class="btn btn-xs btn-ghost" type="button" data-copy="${escapeHTML(doc.syntax)}">${icon('copy', 12)}</button></div>
        <details><summary>What it does, why it matters and gotchas</summary>
          <div class="reference-body">
            <p>${escapeHTML(doc.what)}</p>
            ${doc.security ? `<div class="fix-box"><h4>${icon('shield', 13)} Security</h4><p>${escapeHTML(doc.security)}</p></div>` : ''}
            ${doc.gotchas?.length ? `<h4>Gotchas</h4><ul>${doc.gotchas.map((item) => `<li>${escapeHTML(item)}</li>`).join('')}</ul>` : ''}
            <h4>Example</h4><pre class="reference-example"><code>${escapeHTML(doc.example)}</code></pre>
            <a class="learn-link" href="#/learn/${encodeURIComponent(doc.learn)}">${icon('book', 13)} Learn the concept</a>
          </div>
        </details>
      </article>`).join('') : `<div class="empty-filter">${icon('search', 18)} No directives match this filter.</div>`;
    } else {
      const docs = RECORD_DOCS.filter((doc) => {
        if (category !== 'all' && doc.category !== category) return false;
        if (!needle) return true;
        return `${doc.type} ${doc.name} ${doc.summary} ${doc.what} ${doc.category} ${doc.fields.join(' ')} ${doc.dnssec}`.toLowerCase().includes(needle);
      });
      count.textContent = `${formatNumber(docs.length)} record type${docs.length === 1 ? '' : 's'}`;
      recordList.innerHTML = docs.length ? docs.map((doc) => `<article class="reference-card" id="ref-record-${escapeHTML(doc.type)}">
        <div class="reference-head"><div><span class="eyebrow">${escapeHTML(doc.category)}</span><h2><span class="record-type big">${escapeHTML(doc.type)}</span> ${escapeHTML(doc.name)}</h2></div><div class="meta-strip">${pill(doc.category, 'neutral', 'database')}</div></div>
        <p>${escapeHTML(doc.summary)}</p>
        <div class="syntax-box"><span>fields</span><code>${escapeHTML(doc.fields.join('  '))}</code></div>
        <details><summary>What it does, why it matters and gotchas</summary>
          <div class="reference-body">
            <p>${escapeHTML(doc.what)}</p>
            <p><strong>Why it matters:</strong> ${escapeHTML(doc.why)}</p>
            <div class="fix-box"><h4>${icon('shield', 13)} DNSSEC</h4><p>${escapeHTML(doc.dnssec)}</p></div>
            ${doc.gotchas?.length ? `<h4>Gotchas</h4><ul>${doc.gotchas.map((item) => `<li>${escapeHTML(item)}</li>`).join('')}</ul>` : ''}
            <h4>Example</h4><pre class="reference-example"><code>${escapeHTML(doc.example)}</code></pre>
            <a class="learn-link" href="#/learn/${encodeURIComponent(doc.learn)}">${icon('book', 13)} Learn the concept</a>
          </div>
        </details>
      </article>`).join('') : `<div class="empty-filter">${icon('search', 18)} No record types match this filter.</div>`;
    }
    wireCopyButtons(view);
  }

  function switchTab(next) {
    tab = next;
    view.querySelectorAll('[data-ref-tab]').forEach((button) => button.setAttribute('aria-selected', String(button.dataset.refTab === tab)));
    view.querySelectorAll('[data-ref-panel]').forEach((panel) => {
      panel.hidden = panel.dataset.refPanel !== tab;
    });
    updateCategories();
    paint();
  }

  view.querySelectorAll('[data-ref-tab]').forEach((button) => {
    button.addEventListener('click', () => switchTab(button.dataset.refTab));
  });
  search.addEventListener('input', () => {
    searchTerm = search.value;
    paint();
  });
  categorySelect.addEventListener('change', () => {
    category = categorySelect.value;
    paint();
  });

  updateCategories();
  if (searchTerm && query.get('tab') === 'records') switchTab('records');
  else paint();

  if (query.get('q')) {
    const target = view.querySelector(`#ref-${CSS.escape(query.get('q'))}`) || view.querySelector(`#ref-record-${CSS.escape(query.get('q'))}`);
    if (target) setTimeout(() => target.scrollIntoView({ behavior: 'smooth', block: 'center' }), 60);
  }
  return null;
}
