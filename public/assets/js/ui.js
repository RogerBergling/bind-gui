/* Shared UI primitives, icons, dialogs, toasts and diff rendering. */

import { copyText, escapeHTML, formatNumber } from './utils.js';
import { diffStats, lineDiff } from './dns/diff.js';

const ICONS = {
  home: '<path d="M3 10.5 12 3l9 7.5"/><path d="M5 9.5V21h14V9.5"/><path d="M9 21v-7h6v7"/>',
  grid: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
  shield: '<path d="M12 3 4.5 6v5.2c0 4.8 3.2 8.2 7.5 9.8 4.3-1.6 7.5-5 7.5-9.8V6L12 3Z"/><path d="m8.8 12 2.2 2.2 4.4-4.6"/>',
  database: '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v6c0 1.7 3.6 3 8 3s8-1.3 8-3V5"/><path d="M4 11v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3c2.5 2.6 3.8 5.6 3.8 9S14.5 18.4 12 21c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3Z"/>',
  diff: '<path d="M8 3v18M16 3v18"/><path d="M3 8h5M3 16h5M16 8h5M16 16h5"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3.5 2"/>',
  book: '<path d="M4 5.5A3.5 3.5 0 0 1 7.5 2H20v18H7.5A3.5 3.5 0 0 0 4 23V5.5Z"/><path d="M4 19.5A3.5 3.5 0 0 1 7.5 16H20"/>',
  lock: '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
  upload: '<path d="M12 16V4"/><path d="m7 9 5-5 5 5"/><path d="M4 16v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3"/>',
  download: '<path d="M12 4v12"/><path d="m7 11 5 5 5-5"/><path d="M4 20h16"/>',
  file: '<path d="M6 2h8l5 5v15H6a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2Z"/><path d="M14 2v6h6"/><path d="M8 13h7M8 17h7"/>',
  folder: '<path d="M3 6a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6Z"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  save: '<path d="M5 3h12l3 3v15H4V4a1 1 0 0 1 1-1Z"/><path d="M8 3v6h8V3"/><path d="M8 21v-7h8v7"/>',
  trash: '<path d="M4 7h16"/><path d="M9 7V4h6v3"/><path d="m6 7 1 14h10l1-14"/><path d="M10 11v6M14 11v6"/>',
  refresh: '<path d="M20 12a8 8 0 1 1-2.3-5.7"/><path d="M20 4v6h-6"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="m16.5 16.5 4.5 4.5"/>',
  chevron: '<path d="m9 18 6-6-6-6"/>',
  external: '<path d="M14 4h6v6"/><path d="m20 4-9 9"/><path d="M20 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1h5"/>',
  copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M15 9V5a1 1 0 0 0-1-1H5a1 1 0 0 0-1 1v9a1 1 0 0 0 1 1h4"/>',
  check: '<path d="m4 12.5 5 5L20 6.5"/>',
  warning: '<path d="M12 3 2.5 20h19L12 3Z"/><path d="M12 9v5"/><circle cx="12" cy="17.5" r=".8" fill="currentColor" stroke="none"/>',
  error: '<circle cx="12" cy="12" r="9"/><path d="m8 8 8 8M16 8l-8 8"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6"/><circle cx="12" cy="7.5" r=".8" fill="currentColor" stroke="none"/>',
  close: '<path d="m6 6 12 12M18 6 6 18"/>',
  arrow: '<path d="M4 12h16"/><path d="m14 6 6 6-6 6"/>',
  arrowLeft: '<path d="M20 12H4"/><path d="m10 18-6-6 6-6"/>',
  play: '<path d="m8 5 11 7-11 7V5Z"/>',
  terminal: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3M13 15h4"/>',
  key: '<circle cx="8" cy="15" r="4"/><path d="m11 12 8-8M17 6l2 2M14 9l2 2"/>',
  network: '<rect x="3" y="3" width="6" height="6" rx="1.5"/><rect x="15" y="3" width="6" height="6" rx="1.5"/><rect x="9" y="15" width="6" height="6" rx="1.5"/><path d="M6 9v3h12V9M12 12v3"/>',
  eye: '<path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z"/><circle cx="12" cy="12" r="2.5"/>',
  eyeOff: '<path d="m4 4 16 16"/><path d="M9.9 5.3A10.8 10.8 0 0 1 12 5c6 0 9.5 7 9.5 7a16 16 0 0 1-3.1 3.9M6.3 7.4A17.5 17.5 0 0 0 2.5 12s3.5 7 9.5 7c1 0 1.9-.2 2.8-.6"/><path d="M10.2 10.2a2.5 2.5 0 0 0 3.6 3.6"/>',
  code: '<path d="m8 8-4 4 4 4M16 8l4 4-4 4M13 5l-2 14"/>',
  layers: '<path d="m12 3 9 5-9 5-9-5 9-5Z"/><path d="m3 12 9 5 9-5"/><path d="m3 16 9 5 9-5"/>',
  activity: '<path d="M3 12h4l2-7 4 14 2-7h6"/>',
  filter: '<path d="M3 5h18l-7 8v6l-4 2v-8L3 5Z"/>',
  sparkles: '<path d="m12 3 1.4 4.1L17.5 8.5l-4.1 1.4L12 14l-1.4-4.1-4.1-1.4 4.1-1.4L12 3Z"/><path d="m19 14 .8 2.2L22 17l-2.2.8L19 20l-.8-2.2L16 17l2.2-.8L19 14Z"/>',
  package: '<path d="m12 3 9 5v8l-9 5-9-5V8l9-5Z"/><path d="m3 8 9 5 9-5M12 13v8"/>',
  server: '<rect x="3" y="4" width="18" height="6" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/><path d="M7 7h.01M7 17h.01"/>',
  list: '<path d="M8 6h13M8 12h13M8 18h13"/><path d="M3 6h.01M3 12h.01M3 18h.01"/>',
  zap: '<path d="m13 2-9 12h7l-1 8 9-12h-7l1-8Z"/>',
  edit: '<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L8 18l-4 1 1-4L16.5 3.5Z"/>',
  filePlus: '<path d="M6 2h8l5 5v15H6a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2Z"/><path d="M14 2v6h6M8 14h6M11 11v6"/>',
  sort: '<path d="M8 4v16M4 16l4 4 4-4M16 20V4M12 8l4-4 4 4"/>',
  star: '<path d="m12 3 2.8 5.7 6.2.9-4.5 4.4 1.1 6.2-5.6-3-5.6 3 1.1-6.2L3 9.6l6.2-.9L12 3Z"/>',
  wifi: '<path d="M4 9a13 13 0 0 1 16 0M7 12a8.5 8.5 0 0 1 10 0M10 15a4 4 0 0 1 4 0"/><circle cx="12" cy="19" r=".8" fill="currentColor" stroke="none"/>',
  route: '<circle cx="6" cy="18" r="2.5"/><circle cx="18" cy="6" r="2.5"/><path d="M8.5 18H14a4 4 0 0 0 0-8H9a3.5 3.5 0 0 1 0-7h6"/>',
};

export function icon(name, size = 18, className = '') {
  const path = ICONS[name] || ICONS.info;
  return `<svg class="icon ${className}" viewBox="0 0 24 24" width="${size}" height="${size}" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${path}</svg>`;
}

export function pill(text, tone = '', iconName = null) {
  return `<span class="pill ${tone}">${iconName ? icon(iconName, 13) : ''}${escapeHTML(text)}</span>`;
}

export function pageHead({ eyebrow = '', title, lede = '', actions = '', meta = '' }) {
  return `<div class="page-head">
    <div class="page-head-copy">
      ${eyebrow ? `<span class="eyebrow">${escapeHTML(eyebrow)}</span>` : ''}
      <h1>${escapeHTML(title)}</h1>
      ${lede ? `<p class="page-lede">${lede}</p>` : ''}
      ${meta ? `<div class="meta-strip">${meta}</div>` : ''}
    </div>
    ${actions ? `<div class="page-actions">${actions}</div>` : ''}
  </div>`;
}

export function callout(tone = 'info', title, bodyHtml) {
  const iconName = tone === 'danger' ? 'error' : tone === 'warn' ? 'warning' : tone === 'ok' ? 'check' : 'info';
  return `<div class="callout ${tone}">${icon(iconName, 18)}<div>${title ? `<strong>${escapeHTML(title)}</strong>` : ''}${bodyHtml ? `<div class="callout-body">${bodyHtml}</div>` : ''}</div></div>`;
}

export function emptyState({ title, body, iconName = 'info', actions = '' }) {
  return `<section class="empty-state">
    <div class="empty-icon">${icon(iconName, 26)}</div>
    <h2>${escapeHTML(title)}</h2>
    <p>${body}</p>
    ${actions ? `<div class="empty-actions">${actions}</div>` : ''}
  </section>`;
}

export function stat(value, label, tone = '') {
  return `<div class="stat ${tone}"><strong>${formatNumber(value)}</strong><span>${escapeHTML(label)}</span></div>`;
}

export function toast(message, tone = 'ok') {
  let node = document.getElementById('toast');
  if (!node) {
    node = document.createElement('div');
    node.id = 'toast';
    node.className = 'toast';
    node.setAttribute('role', 'status');
    node.setAttribute('aria-live', 'polite');
    document.body.append(node);
  }
  node.textContent = message;
  node.dataset.tone = tone;
  node.classList.add('visible');
  clearTimeout(node._timer);
  node._timer = setTimeout(() => node.classList.remove('visible'), 3600);
}

export function openModal({ title = '', lede = '', body = '', actions = '', wide = false, onMount = null }) {
  const dialog = document.createElement('dialog');
  dialog.className = `modal ${wide ? 'modal-wide' : ''}`;
  dialog.innerHTML = `<div class="modal-card">
    <div class="modal-head">
      <div>
        ${title ? `<h2>${escapeHTML(title)}</h2>` : ''}
        ${lede ? `<p class="modal-lede">${lede}</p>` : ''}
      </div>
      <button class="btn btn-icon modal-close" type="button" aria-label="Close dialog" data-modal-close>${icon('close')}</button>
    </div>
    <div class="modal-body">${body}</div>
    <div class="modal-actions">
      ${actions || `<button class="btn" type="button" data-modal-close>Close</button>`}
    </div>
  </div>`;
  document.body.append(dialog);
  const close = () => {
    if (dialog.open) dialog.close();
    dialog.remove();
  };
  dialog.addEventListener('click', (event) => {
    if (event.target === dialog) close();
    if (event.target.closest('[data-modal-close]')) close();
  });
  dialog.addEventListener('cancel', (event) => {
    event.preventDefault();
    close();
  });
  dialog.addEventListener('close', () => dialog.remove());
  dialog.showModal();
  if (typeof onMount === 'function') onMount(dialog, close);
  return { dialog, close };
}

export function confirmDialog({ title, message, confirmLabel = 'Confirm', tone = 'danger' }) {
  return new Promise((resolve) => {
    let settled = false;
    const { dialog, close } = openModal({
      title,
      body: `<p>${message}</p>`,
      actions: `<button class="btn btn-ghost" type="button" data-choice="cancel">Cancel</button>
        <button class="btn ${tone === 'danger' ? 'btn-danger' : 'btn-primary'}" type="button" data-choice="confirm">${escapeHTML(confirmLabel)}</button>`,
    });
    const finish = (value) => {
      if (settled) return;
      settled = true;
      resolve(value);
      close();
    };
    dialog.querySelector('[data-choice="cancel"]')?.addEventListener('click', () => finish(false));
    dialog.querySelector('[data-choice="confirm"]')?.addEventListener('click', () => finish(true));
    dialog.addEventListener('click', (event) => {
      if (event.target.closest('[data-modal-close]')) finish(false);
    });
    dialog.addEventListener('cancel', () => finish(false));
  });
}

export function wireCopyButtons(root = document) {
  root.querySelectorAll('[data-copy]').forEach((button) => {
    if (button.dataset.wired === 'true') return;
    button.dataset.wired = 'true';
    button.addEventListener('click', async () => {
      const selector = button.dataset.copyTarget;
      const text = selector
        ? root.querySelector(selector)?.textContent || ''
        : button.dataset.copy || '';
      const ok = await copyText(text);
      toast(ok ? 'Copied to the clipboard.' : 'Could not copy. Select the text manually.', ok ? 'ok' : 'danger');
    });
  });
}

export function codeBlock(text, { label = '', copy = true, className = '' } = {}) {
  return `<div class="code-block ${className}">
    <div class="code-head"><span>${escapeHTML(label || 'code')}</span>${copy ? `<button class="btn btn-xs btn-ghost" type="button" data-copy="${escapeHTML(text)}">${icon('copy', 13)} Copy</button>` : ''}</div>
    <pre><code>${escapeHTML(text)}</code></pre>
  </div>`;
}

export function diffSummary(operations) {
  const stats = diffStats(operations);
  if (stats.identical) return `<div class="diff-summary identical">${icon('check', 14)} Identical — no line changes.</div>`;
  return `<div class="diff-summary"><span class="diff-chip add">+${formatNumber(stats.added)}</span><span class="diff-chip del">−${formatNumber(stats.deleted)}</span><span class="diff-chip same">${formatNumber(stats.same)} unchanged</span><span class="diff-chip same">${formatNumber(stats.hunks)} hunk${stats.hunks === 1 ? '' : 's'}</span></div>`;
}

export function renderDiff(operations, { maxRows = 5000, emptyText = 'The two inputs are identical.' } = {}) {
  if (!operations.length) return `<div class="diff-empty">${escapeHTML(emptyText)}</div>`;
  const stats = diffStats(operations);
  if (stats.identical) return `<div class="diff-empty">${escapeHTML(emptyText)}</div>`;
  const rows = operations.slice(0, maxRows).map((operation) => {
    const sign = operation.type === 'add' ? '+' : operation.type === 'del' ? '−' : ' ';
    const aNumber = operation.aLine === undefined ? '' : operation.aLine + 1;
    const bNumber = operation.bLine === undefined ? '' : operation.bLine + 1;
    return `<div class="diff-row ${operation.type}"><span class="diff-sign">${sign}</span><span class="diff-num">${aNumber}</span><span class="diff-num">${bNumber}</span><code>${escapeHTML(operation.text)}</code></div>`;
  }).join('');
  return `<div class="diff">
    <div class="diff-head"><span>old</span><span>new</span><div class="diff-legend">${diffSummary(operations)}</div></div>
    <div class="diff-body">${rows}</div>
    ${operations.length > maxRows ? `<div class="diff-empty">Showing the first ${formatNumber(maxRows)} of ${formatNumber(operations.length)} diff rows. Use the download or compare a smaller file for the rest.</div>` : ''}
  </div>`;
}

export function renderTextDiff(a, b, options = {}) {
  return renderDiff(lineDiff(a, b), options);
}

export function severityIcon(severity) {
  return icon(severity === 'error' ? 'error' : severity === 'warning' ? 'warning' : severity === 'recommendation' ? 'info' : 'check', 16);
}

export function scoreTone(score) {
  if (score >= 90) return 'ok';
  if (score >= 75) return 'accent';
  if (score >= 60) return 'warn';
  return 'danger';
}

export function scoreGauge(score, label = 'score') {
  return `<div class="score-gauge" style="--score:${Math.max(0, Math.min(100, Number(score) || 0))}">
    <div class="score-gauge-inner"><strong>${Number(score) || 0}</strong><span>${escapeHTML(label)}</span></div>
  </div>`;
}

export function sectionHead(title, description = '', actions = '') {
  return `<div class="section-head"><div>${description ? `<p>${description}</p>` : ''}<h2>${escapeHTML(title)}</h2></div>${actions}</div>`;
}

export function externalLink(href, text, iconName = 'external') {
  return `<a href="${escapeHTML(href)}" target="_blank" rel="noopener noreferrer">${escapeHTML(text)} ${icon(iconName, 13)}</a>`;
}
