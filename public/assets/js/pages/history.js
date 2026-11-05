/* Local snapshot history: restore, compare, download and clean up. */

import {
  clearHistory,
  deleteSnapshot,
  exportHistoryJson,
  getCurrentWorkspace,
  getHistory,
  restoreSnapshot,
  saveSnapshot,
  storageStats,
} from '../storage.js';
import { downloadWorkspaceJson } from '../dns/export.js';
import { icon, pill, scoreGauge, toast, confirmDialog } from '../ui.js';
import { downloadText, escapeHTML, formatBytes, formatDateTime, formatNumber, timeAgo } from '../utils.js';

export function renderHistory(view) {
  const current = getCurrentWorkspace();
  const history = getHistory();
  const stats = storageStats();
  const percent = Math.min(100, Math.round((stats.totalBytes / 4_200_000) * 100));

  view.innerHTML = `<div class="page-head">
    <div class="page-head-copy"><span class="eyebrow">History · browser-local</span><h1>Every version you chose to keep</h1><p class="page-lede">Snapshots are created on import, manual save, export and restore. Up to 100 versions are stored in this browser; nothing is sent to the server. Restores create a new snapshot, so a rollback can itself be undone.</p><div class="meta-strip">${pill(`${history.length} snapshots`, 'accent', 'clock')}${pill(`${formatBytes(stats.totalBytes)} used`, percent > 85 ? 'warn' : 'neutral', 'database')}${pill(`${stats.limit} limit`, 'neutral', 'list')}</div></div>
    <div class="page-actions">${current ? `<button class="btn btn-primary" type="button" id="snapshot-current">${icon('save', 16)} Snapshot current</button>` : `<a class="btn btn-primary" href="#/workbench">${icon('upload', 16)} Import a workspace</a>`}<button class="btn" type="button" id="export-history">${icon('download', 16)} Export JSON</button><button class="btn btn-danger btn-ghost" type="button" id="clear-history">${icon('trash', 16)} Clear</button></div>
  </div>
  <div class="storage-card">
    <div><strong>Browser storage</strong><span>${formatBytes(stats.totalBytes)} of an approximate 4.2 MB self-imposed budget</span></div>
    <div class="storage-meter"><span style="width:${percent}%"></span></div>
    <div class="storage-numbers"><span>${stats.snapshots} / ${stats.limit} snapshots</span><span>current workspace ${formatBytes(stats.currentBytes)}</span><span>history ${formatBytes(stats.historyBytes)}</span></div>
  </div>

  ${current ? `<div class="resume-card history-current">
    <div class="resume-main"><span class="eyebrow">Current workspace</span><h2>${escapeHTML(current.name)}</h2><p class="resume-meta">${formatNumber(current.files.length)} files · updated ${escapeHTML(formatDateTime(current.updatedAt))}</p><div class="meta-strip">${pill('editable now', 'ok', 'edit')}${pill(current.entry || 'no entry', 'neutral', 'file')}</div></div>
    <div class="resume-actions"><a class="btn btn-primary" href="#/workbench">${icon('edit', 16)} Open workbench</a><a class="btn" href="#/compare">${icon('diff', 16)} Compare files</a></div>
  </div>` : ''}

  ${history.length ? `<div class="history-list">${history.map((snapshot) => {
    const counts = snapshot.counts || null;
    return `<article class="history-card">
      <div class="history-score">${snapshot.score === null || snapshot.score === undefined ? `<div class="score-placeholder">${icon('clock', 20)}</div>` : scoreGauge(snapshot.score, 'score')}</div>
      <div class="history-main">
        <div class="history-head"><span class="eyebrow">${escapeHTML(snapshot.label || snapshot.source)}</span>${pill(snapshot.source || 'save', 'neutral', 'save')}${counts ? pill(`${counts.error || 0} errors`, counts.error ? 'danger' : 'ok', 'error') : ''}${counts ? pill(`${counts.warning || 0} warnings`, counts.warning ? 'warn' : 'ok', 'warning') : ''}</div>
        <h2>${escapeHTML(snapshot.name)}</h2>
        <p class="resume-meta">${escapeHTML(formatDateTime(snapshot.createdAt))} · ${escapeHTML(timeAgo(snapshot.createdAt))} · ${formatNumber(snapshot.files)} files${snapshot.zones ? ` · ${formatNumber(snapshot.zones)} zones` : ''} · ${formatBytes(snapshot.bytes || 0)}</p>
        <div class="history-actions">
          <button class="btn btn-sm btn-primary" type="button" data-restore="${escapeHTML(snapshot.id)}">${icon('refresh', 14)} Restore</button>
          <a class="btn btn-sm" href="#/compare?mode=snapshot&snapshot=${encodeURIComponent(snapshot.id)}">${icon('diff', 14)} Compare current</a>
          <button class="btn btn-sm btn-ghost" type="button" data-download-snapshot="${escapeHTML(snapshot.id)}">${icon('download', 14)} JSON</button>
          <button class="btn btn-sm btn-danger btn-ghost" type="button" data-delete-snapshot="${escapeHTML(snapshot.id)}">${icon('trash', 14)} Delete</button>
        </div>
      </div>
    </article>`;
  }).join('')}</div>` : `<div class="empty-state"><div class="empty-icon">${icon('clock', 26)}</div><h2>No snapshots yet</h2><p>Import a workspace or press <strong>Save snapshot</strong> in the workbench. Snapshots let you compare and restore without Git or a server database.</p><div class="empty-actions"><a class="btn btn-primary" href="#/workbench">${icon('code', 16)} Open workbench</a><a class="btn" href="#/learn/change-workflow">${icon('book', 16)} Safe change workflow</a></div></div>`}

  <div class="callout warn">${icon('warning', 18)}<div><strong>Browser storage is not a backup</strong><p>Clearing site data, using a private window or losing the device deletes this history. Export snapshots that matter. Snapshots may contain TSIG secrets or key material that was present in the imported files.</p></div></div>
  `;

  view.querySelector('#snapshot-current')?.addEventListener('click', () => {
    if (!current) return;
    const result = saveSnapshot(current, { label: 'Manual snapshot', source: 'save' });
    toast(result.ok ? (result.deduplicated ? 'Snapshot updated (content unchanged).' : 'Snapshot saved.') : result.error, result.ok ? 'ok' : 'danger');
    if (result.ok) window.dispatchEvent(new Event('workbench:reload'));
  });
  view.querySelector('#export-history')?.addEventListener('click', () => {
    downloadText('bind-workbench-history.json', exportHistoryJson(), 'application/json');
    toast('History JSON downloaded.', 'ok');
  });
  view.querySelector('#clear-history')?.addEventListener('click', async () => {
    const ok = await confirmDialog({
      title: 'Clear all snapshots?',
      message: 'This removes every saved snapshot from this browser. The current workspace is not deleted. Export anything you need first.',
      confirmLabel: 'Clear history',
    });
    if (!ok) return;
    clearHistory();
    toast('History cleared.', 'ok');
    window.dispatchEvent(new Event('workbench:reload'));
  });
  view.querySelectorAll('[data-restore]').forEach((button) => {
    button.addEventListener('click', async () => {
      const snapshot = history.find((item) => item.id === button.dataset.restore);
      if (!snapshot) return;
      const ok = await confirmDialog({
        title: 'Restore this snapshot?',
        message: `Restore <strong>${escapeHTML(snapshot.name)}</strong> from ${escapeHTML(formatDateTime(snapshot.createdAt))}? The current workspace is snapshotted first, so this can be undone.`,
        confirmLabel: 'Restore snapshot',
        tone: 'primary',
      });
      if (!ok) return;
      const result = restoreSnapshot(snapshot.id);
      if (!result.ok) {
        toast(result.error || 'Restore failed.', 'danger');
        return;
      }
      toast('Snapshot restored. The previous current workspace was saved first.', 'ok');
      location.hash = '#/workbench';
    });
  });
  view.querySelectorAll('[data-download-snapshot]').forEach((button) => {
    button.addEventListener('click', () => {
      const snapshot = history.find((item) => item.id === button.dataset.downloadSnapshot);
      if (!snapshot) return;
      downloadWorkspaceJson(snapshot.workspace);
      toast('Snapshot JSON downloaded.', 'ok');
    });
  });
  view.querySelectorAll('[data-delete-snapshot]').forEach((button) => {
    button.addEventListener('click', async () => {
      const ok = await confirmDialog({
        title: 'Delete this snapshot?',
        message: 'This removes the snapshot from browser storage. It cannot be undone.',
        confirmLabel: 'Delete snapshot',
      });
      if (!ok) return;
      deleteSnapshot(button.dataset.deleteSnapshot);
      toast('Snapshot deleted.', 'ok');
      window.dispatchEvent(new Event('workbench:reload'));
    });
  });
  return null;
}
