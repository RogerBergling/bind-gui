/* Learning library index and article reader. */

import { ARTICLES, LEARNING_PATHS, articleById } from '../data/learn.js';
import { GLOSSARY } from '../data/glossary.js';
import { DIRECTIVE_DOCS } from '../data/directives.js';
import { RECORD_DOCS } from '../data/records.js';
import { getCurrentWorkspace } from '../storage.js';
import { icon, pill, emptyState } from '../ui.js';
import { escapeHTML, formatNumber } from '../utils.js';

export function renderLearn(view, param, query) {
  const article = param ? articleById(param) : null;
  if (param && !article) {
    view.innerHTML = emptyState({
      title: 'Article not found',
      body: `There is no learning article with the id <code>${escapeHTML(param)}</code>.`,
      iconName: 'book',
      actions: `<a class="btn btn-primary" href="#/learn">${icon('book', 16)} Back to learning</a>`,
    });
    return null;
  }

  if (article) {
    renderArticle(view, article);
    return null;
  }

  const current = getCurrentWorkspace();
  view.innerHTML = `<div class="page-head">
    <div class="page-head-copy"><span class="eyebrow">Learn</span><h1>DNS is a system, not a syntax</h1><p class="page-lede">Long-form explanations written for operators: the mental model, zone files, delegation, DNSSEC, recursion security, transfers, views, operations and the safe change workflow. Every analyzer finding links back here.</p><div class="meta-strip">${pill(`${ARTICLES.length} articles`, 'accent', 'book')}${pill(`${DIRECTIVE_DOCS.length} directives`, 'neutral', 'file')}${pill(`${RECORD_DOCS.length} record types`, 'neutral', 'database')}${pill(`${GLOSSARY.length} terms`, 'neutral', 'list')}</div></div>
    <div class="page-actions"><a class="btn" href="#/reference">${icon('code', 16)} Reference</a><a class="btn" href="#/glossary">${icon('book', 16)} Glossary</a>${current ? `<a class="btn btn-primary" href="#/workbench?tab=learn">${icon('edit', 16)} Learn this config</a>` : ''}</div>
  </div>

  <div class="filterbar">
    <div class="search-field">${icon('search', 15)}<input type="search" id="learn-search" placeholder="Search articles, tags and concepts…" aria-label="Search learning articles"></div>
    <span class="filter-result" id="learn-count">${ARTICLES.length} articles</span>
  </div>

  <section class="learning-lab-card">
    <div class="learning-lab-copy">
      <span class="eyebrow">Companion learning site</span>
      <h2>More simulations, quizzes and a wider operations library</h2>
      <p><a href="https://learning.bergling.net" target="_blank" rel="noopener noreferrer">learning.bergling.net</a> is an independent, browser-local learning lab covering six tracks: OneGate federation, Docker on Linux, Git &amp; GHCR, HAProxy, ESXi performance and BIND DNS. It contains written chapters, animated flow simulations, credential and token walkthroughs, side-by-side comparisons, a glossary, quizzes and self-checks. Everything runs in the browser; the examples and simulated credentials are illustrative rather than production configuration.</p>
      <div class="link-row"><a class="btn btn-primary" href="https://learning.bergling.net" target="_blank" rel="noopener noreferrer">${icon('external', 15)} Open Learning Lab</a><span class="muted-note">${icon('info', 14)} Best for visual flow practice and self-testing alongside these BIND guides.</span></div>
    </div>
    <div class="learning-lab-topics">
      <span>OneGate federation</span><span>Docker on Linux</span><span>Git &amp; GHCR</span><span>HAProxy</span><span>ESXi performance</span><span>BIND DNS</span>
    </div>
  </section>

  <div class="learning-paths">${LEARNING_PATHS.map((path) => `<article class="learning-path">
    <span class="eyebrow">Path</span><h2>${escapeHTML(path.title)}</h2><p>${escapeHTML(path.description)}</p>
    <div class="path-steps">${path.articles.map((id, index) => {
      const item = articleById(id);
      return item ? `<a href="#/learn/${encodeURIComponent(id)}"><span>${index + 1}</span>${escapeHTML(item.title)}${icon('arrow', 13)}</a>` : '';
    }).join('')}</div>
  </article>`).join('')}</div>

  <div class="section-head small"><h2>All guides</h2><p>Start anywhere; the articles link to the relevant reference entries and glossary terms.</p></div>
  <div class="article-grid" id="article-grid">${ARTICLES.map(renderArticleCard).join('')}</div>

  <div class="split-block learn-bottom">
    <div><span class="eyebrow">In context</span><h2>Learn your own configuration</h2><p>The Workbench’s <strong>Learn this config</strong> tab walks every directive in your actual file, with its context and a link to the full reference. Findings on the Analyze page link to the concept behind the rule.</p><div class="link-row">${current ? `<a class="btn btn-primary" href="#/workbench?tab=learn">${icon('edit', 16)} Open learn-this-config</a>` : `<a class="btn btn-primary" href="#/workbench">${icon('upload', 16)} Import a config</a>`}<a class="btn" href="#/reference">Reference</a></div></div>
    <div class="privacy-facts"><div class="fact">${icon('book', 18)}<div><strong>Deep, not decorative</strong><span>Each guide explains what changes, why it matters and the failure mode.</span></div></div><div class="fact">${icon('shield', 18)}<div><strong>Security first</strong><span>Recursion, transfers, updates and DNSSEC are treated as operational risks, not features.</span></div></div><div class="fact">${icon('route', 18)}<div><strong>Workflow included</strong><span>Compare, validate, export, deploy and verify.</span></div></div></div>
  </div>
  `;

  const search = view.querySelector('#learn-search');
  const grid = view.querySelector('#article-grid');
  const count = view.querySelector('#learn-count');
  search.addEventListener('input', () => {
    const term = search.value.toLowerCase().trim();
    const filtered = ARTICLES.filter((item) => `${item.title} ${item.summary} ${item.tags.join(' ')} ${item.level}`.toLowerCase().includes(term));
    grid.innerHTML = filtered.map(renderArticleCard).join('') || `<div class="empty-filter">${icon('search', 18)} No articles match “${escapeHTML(search.value)}”.</div>`;
    count.textContent = `${formatNumber(filtered.length)} article${filtered.length === 1 ? '' : 's'}`;
  });
  return null;
}

function renderArticleCard(article) {
  return `<a class="article-card" href="#/learn/${encodeURIComponent(article.id)}">
    <div class="article-card-top"><span class="pill violet">${escapeHTML(article.level)}</span><span class="muted">${article.minutes} min</span></div>
    <h2>${escapeHTML(article.title)}</h2>
    <p>${escapeHTML(article.summary)}</p>
    <div class="article-tags">${article.tags.map((tag) => `<span>${escapeHTML(tag)}</span>`).join('')}</div>
    <span class="feature-link">Read ${icon('arrow', 13)}</span>
  </a>`;
}

function renderArticle(view, article) {
  const index = ARTICLES.findIndex((item) => item.id === article.id);
  const previous = index > 0 ? ARTICLES[index - 1] : null;
  const next = index >= 0 && index < ARTICLES.length - 1 ? ARTICLES[index + 1] : null;
  view.innerHTML = `<div class="article-layout">
    <aside class="article-toc">
      <a class="back-link" href="#/learn">${icon('arrowLeft', 15)} All guides</a>
      <div class="toc-head">On this page</div>
      <nav>${article.sections.map((section) => `<a href="#/learn/${encodeURIComponent(article.id)}#${escapeHTML(section.id)}" data-toc="${escapeHTML(section.id)}">${escapeHTML(section.title)}</a>`).join('')}</nav>
      <div class="toc-foot"><a class="btn btn-sm btn-ghost" href="#/reference">${icon('code', 14)} Reference</a><a class="btn btn-sm btn-ghost" href="#/glossary">${icon('book', 14)} Glossary</a></div>
    </aside>
    <article class="article">
      <a class="back-link mobile-back" href="#/learn">${icon('arrowLeft', 15)} All guides</a>
      <span class="eyebrow">${escapeHTML(article.level)} · ${article.minutes} min read</span>
      <h1>${escapeHTML(article.title)}</h1>
      <p class="article-lede">${escapeHTML(article.summary)}</p>
      <div class="article-tags">${article.tags.map((tag) => `<span>${escapeHTML(tag)}</span>`).join('')}</div>
      ${article.sections.map((section) => `<section class="doc-section" id="${escapeHTML(section.id)}"><h2>${escapeHTML(section.title)}</h2>${section.html}</section>`).join('')}
      <div class="article-pager">${previous ? `<a class="pager-card" href="#/learn/${encodeURIComponent(previous.id)}"><span>${icon('arrowLeft', 14)} Previous</span><strong>${escapeHTML(previous.title)}</strong></a>` : '<span></span>'}${next ? `<a class="pager-card next" href="#/learn/${encodeURIComponent(next.id)}"><span>Next ${icon('arrow', 14)}</span><strong>${escapeHTML(next.title)}</strong></a>` : '<span></span>'}</div>
      <div class="callout info">${icon('info', 18)}<div><strong>Keep going</strong><p>Use the analyzer on your own workspace, then compare the candidate version with the current one before exporting. The learning content complements, but never replaces, the official BIND documentation and the exact BIND binary you deploy.</p></div></div>
    </article>
  </div>`;

  view.querySelectorAll('[data-toc]').forEach((link) => {
    link.addEventListener('click', (event) => {
      const target = view.querySelector(`#${CSS.escape(link.dataset.toc)}`);
      if (!target) return;
      event.preventDefault();
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      history.replaceState(null, '', `#/learn/${encodeURIComponent(article.id)}#${link.dataset.toc}`);
    });
  });
  const deepSection = location.hash.split('#')[2];
  if (deepSection) {
    setTimeout(() => view.querySelector(`#${CSS.escape(deepSection)}`)?.scrollIntoView({ block: 'start' }), 60);
  }
}
