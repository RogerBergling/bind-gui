/* Searchable DNS/BIND glossary. */

import { GLOSSARY } from '../data/glossary.js';
import { icon, pill } from '../ui.js';
import { escapeHTML, formatNumber } from '../utils.js';

export function renderGlossary(view, query) {
  const initial = query.get('q') || '';
  const sorted = GLOSSARY.slice().sort((left, right) => left.term.localeCompare(right.term));
  view.innerHTML = `<div class="page-head">
    <div class="page-head-copy"><span class="eyebrow">Glossary</span><h1>The words operators actually use</h1><p class="page-lede">${GLOSSARY.length} DNS and BIND terms, from AA and AD to zone cuts and ZSK. Each entry links to the deeper explanation where it matters.</p><div class="meta-strip">${pill(`${GLOSSARY.length} terms`, 'accent', 'book')}${pill('searchable', 'neutral', 'search')}${pill('linked to guides', 'neutral', 'arrow')}</div></div>
    <div class="page-actions"><a class="btn" href="#/learn">${icon('book', 16)} Learning guides</a><a class="btn" href="#/reference">${icon('code', 16)} Reference</a></div>
  </div>
  <div class="filterbar"><div class="search-field">${icon('search', 15)}<input type="search" id="glossary-search" value="${escapeHTML(initial)}" placeholder="Search a term, alias or definition…" aria-label="Search glossary"></div><span class="filter-result" id="glossary-count">${GLOSSARY.length} terms</span></div>
  <div class="glossary-list" id="glossary-list"></div>
  <div class="callout info">${icon('info', 18)}<div><strong>Aliases matter</strong><p>BIND and the RFCs often use several words for the same idea (primary/master, secondary/slave, primaries/masters, zone cut/delegation point). Search either form.</p></div></div>`;

  const list = view.querySelector('#glossary-list');
  const count = view.querySelector('#glossary-count');
  const search = view.querySelector('#glossary-search');

  function paint(term = '') {
    const needle = term.toLowerCase().trim();
    const filtered = sorted.filter((item) => `${item.term} ${item.aliases.join(' ')} ${item.definition}`.toLowerCase().includes(needle));
    count.textContent = `${formatNumber(filtered.length)} term${filtered.length === 1 ? '' : 's'}`;
    list.innerHTML = filtered.length ? filtered.map((item) => `<article class="glossary-item">
      <div class="glossary-term"><h2>${escapeHTML(item.term)}</h2>${item.aliases.length ? `<span>${item.aliases.map(escapeHTML).join(' · ')}</span>` : ''}</div>
      <p>${escapeHTML(item.definition)}</p>
      <a class="learn-link" href="#/learn/${encodeURIComponent(item.learn)}">${icon('book', 13)} Read the guide</a>
    </article>`).join('') : `<div class="empty-filter">${icon('search', 18)} No terms match “${escapeHTML(term)}”.</div>`;
  }

  search.addEventListener('input', () => paint(search.value));
  paint(initial);
  return null;
}
