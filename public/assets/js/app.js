import { applyBuildInfo, loadBuildInfo } from './version.js';
import { getSettings, saveSettings } from './storage.js';
import { CURRENT_KEY, HISTORY_KEY, SETTINGS_KEY } from './storage.js';
import { initAuth } from './auth.js';
import { icon } from './ui.js';

const view = document.getElementById('view');
const themeToggle = document.getElementById('theme-toggle');
let activeCleanup = null;
let renderSequence = 0;

const TITLES = {
  home: 'BIND Workbench — DNS config studio',
  workbench: 'Workbench · BIND Workbench',
  analyze: 'Analyze · BIND Workbench',
  zones: 'Zones · BIND Workbench',
  live: 'Live DNS · BIND Workbench',
  compare: 'Compare · BIND Workbench',
  history: 'History · BIND Workbench',
  learn: 'Learn · BIND Workbench',
  glossary: 'Glossary · BIND Workbench',
  reference: 'Reference · BIND Workbench',
  security: 'Security & privacy · BIND Workbench',
  notfound: 'Not found · BIND Workbench',
};

function parseRoute() {
  const raw = location.hash.replace(/^#/, '') || '/';
  const [beforeQuery, queryPart = ''] = raw.split('?');
  const [pathPart, fragment = ''] = beforeQuery.split('#');
  const segments = pathPart.replace(/^\/+|\/+$/g, '').split('/').filter(Boolean);
  const page = segments[0] || 'home';
  const param = segments.slice(1).join('/');
  return { page, param, fragment, query: new URLSearchParams(queryPart) };
}

function setNav(page) {
  const map = {
    home: 'home',
    workbench: 'workbench',
    analyze: 'analyze',
    zones: 'zones',
    live: 'live',
    compare: 'compare',
    history: 'history',
    learn: 'learn',
    glossary: 'learn',
    reference: 'learn',
    security: '',
    notfound: '',
  };
  document.querySelectorAll('.nav a').forEach((anchor) => {
    const active = Boolean(map[page]) && anchor.dataset.nav === map[page];
    anchor.classList.toggle('active', active);
    if (active) anchor.setAttribute('aria-current', 'page');
    else anchor.removeAttribute('aria-current');
  });
}

async function loadPage(page, param, query) {
  switch (page) {
    case 'home': {
      const { renderHome } = await import('./pages/home.js');
      return renderHome(view, query);
    }
    case 'workbench': {
      const { renderWorkbench } = await import('./pages/workbench.js');
      return renderWorkbench(view, param, query);
    }
    case 'analyze': {
      const { renderAnalyze } = await import('./pages/analyze.js');
      return renderAnalyze(view, query);
    }
    case 'zones': {
      const { renderZones } = await import('./pages/zones.js');
      return renderZones(view, param, query);
    }
    case 'live': {
      const { renderLive } = await import('./pages/live.js');
      return renderLive(view, query);
    }
    case 'compare': {
      const { renderCompare } = await import('./pages/compare.js');
      return renderCompare(view, query);
    }
    case 'history': {
      const { renderHistory } = await import('./pages/history.js');
      return renderHistory(view, query);
    }
    case 'learn': {
      const { renderLearn } = await import('./pages/learn.js');
      return renderLearn(view, param, query);
    }
    case 'glossary': {
      const { renderGlossary } = await import('./pages/glossary.js');
      return renderGlossary(view, query);
    }
    case 'reference': {
      const { renderReference } = await import('./pages/reference.js');
      return renderReference(view, query);
    }
    case 'security': {
      const { renderSecurity } = await import('./pages/security.js');
      return renderSecurity(view, query);
    }
    default:
      return renderNotFound(view, page);
  }
}

function renderNotFound(target, page) {
  target.innerHTML = `<section class="empty-state">
    <div class="empty-icon">${icon('search', 26)}</div>
    <h2>Page not found</h2>
    <p>There is no route for <code>${escapeHTML(page)}</code>. The address may be mistyped, or a link may be from an older version.</p>
    <div class="empty-actions">
      <a class="btn btn-primary" href="#/">${icon('home', 16)} Go home</a>
      <a class="btn btn-ghost" href="#/workbench">Open workbench</a>
    </div>
  </section>`;
  return null;
}

function escapeHTML(value) {
  return String(value ?? '').replace(/[&<>"']/g, (char) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[char]));
}

function showLoading() {
  view.innerHTML = `<div class="loading" role="status"><span class="spinner"></span> Loading the workbench…</div>`;
}

function showError(error) {
  console.error(error);
  view.innerHTML = `<section class="empty-state">
    <div class="empty-icon error">${icon('warning', 26)}</div>
    <h2>This view could not be loaded</h2>
    <p>The application hit an unexpected error while rendering. Reload the page to try again. Your browser-local configuration has not been changed.</p>
    <div class="empty-actions">
      <button class="btn btn-primary" type="button" data-action="reload">${icon('refresh', 16)} Reload</button>
      <a class="btn btn-ghost" href="#/">Go home</a>
    </div>
    <details class="error-detail"><summary>Technical detail</summary><pre>${escapeHTML(error?.stack || error?.message || String(error))}</pre></details>
  </section>`;
  view.querySelector('[data-action="reload"]')?.addEventListener('click', () => location.reload());
}

async function render() {
  const sequence = ++renderSequence;
  const { page, param, query } = parseRoute();
  const isCurrent = () => sequence === renderSequence;

  if (typeof activeCleanup === 'function') {
    try {
      activeCleanup();
    } catch (error) {
      console.warn('Page cleanup failed', error);
    }
  }
  activeCleanup = null;

  setNav(page);
  document.title = TITLES[page] || TITLES.notfound;

  if (!location.hash) history.replaceState(null, '', '#/');

  showLoading();
  view.className = 'view';
  window.scrollTo({ top: 0, behavior: 'instant' });

  try {
    const cleanup = await loadPage(page, param, query);
    if (!isCurrent()) {
      if (typeof cleanup === 'function') cleanup();
      return;
    }
    activeCleanup = typeof cleanup === 'function' ? cleanup : null;
    const info = await loadBuildInfo();
    if (isCurrent()) applyBuildInfo(document, info);
  } catch (error) {
    if (isCurrent()) showError(error);
    return;
  }

  view.focus({ preventScroll: true });
}

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  document.documentElement.style.colorScheme = theme;
  if (themeToggle) {
    themeToggle.setAttribute('aria-pressed', theme === 'light' ? 'true' : 'false');
    themeToggle.setAttribute('aria-label', theme === 'light' ? 'Switch to dark theme' : 'Switch to light theme');
    themeToggle.title = theme === 'light' ? 'Switch to dark theme' : 'Switch to light theme';
  }
}

function initTheme() {
  const settings = getSettings();
  const systemLight = window.matchMedia?.('(prefers-color-scheme: light)')?.matches;
  applyTheme(settings.theme || (systemLight ? 'light' : 'dark'));
  themeToggle?.addEventListener('click', () => {
    const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
    applyTheme(next);
    saveSettings({ theme: next });
  });
}

function initShortcuts() {
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      const dialog = document.querySelector('dialog[open]');
      if (dialog) dialog.close();
    }
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 's') {
      if (location.hash.startsWith('#/workbench')) {
        event.preventDefault();
        window.dispatchEvent(new Event('workbench:save'));
      }
    }
  });
}

window.addEventListener('hashchange', render);
window.addEventListener('workbench:reload', render);
window.addEventListener('storage', (event) => {
  if ([CURRENT_KEY, HISTORY_KEY, SETTINGS_KEY].includes(event.key)) render();
});
window.addEventListener('workbench:data', (event) => {
  if (event.detail?.type !== 'settings') return;
  const settings = getSettings();
  const systemLight = window.matchMedia?.('(prefers-color-scheme: light)')?.matches;
  applyTheme(settings.theme || (systemLight ? 'light' : 'dark'));
});

initTheme();
initShortcuts();
initAuth();
loadBuildInfo().then((info) => applyBuildInfo(document, info));
render();
