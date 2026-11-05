/* Browser-local storage for the current workspace, snapshots and settings. */

import { workspaceFingerprint } from './dns/workspace.js';

const PREFIX = 'bind-workbench:v1';
export const CURRENT_KEY = `${PREFIX}:current`;
export const HISTORY_KEY = `${PREFIX}:history`;
export const SETTINGS_KEY = `${PREFIX}:settings`;

const DEFAULT_SETTINGS = {
  theme: null,
  onlineConsent: false,
  resolver: 'cloudflare',
  historyLimit: 100,
  showSecrets: false,
};

function storage() {
  return globalThis.localStorage || null;
}

function readJSON(key, fallback) {
  const store = storage();
  if (!store) return fallback;
  try {
    const raw = store.getItem(key);
    return raw ? JSON.parse(raw) : fallback;
  } catch {
    return fallback;
  }
}

function writeJSON(key, value) {
  const store = storage();
  if (!store) return { ok: false, error: 'localStorage is unavailable.' };
  try {
    store.setItem(key, JSON.stringify(value));
    return { ok: true };
  } catch (error) {
    return { ok: false, error: error?.message || 'The browser storage quota was exceeded.' };
  }
}

export function getSettings() {
  return { ...DEFAULT_SETTINGS, ...readJSON(SETTINGS_KEY, {}) };
}

export function saveSettings(patch) {
  const next = { ...getSettings(), ...patch };
  const result = writeJSON(SETTINGS_KEY, next);
  return { ...result, settings: next };
}

export function getCurrentWorkspace() {
  const value = readJSON(CURRENT_KEY, null);
  if (!value || !Array.isArray(value.files)) return null;
  return value;
}

export function saveCurrentWorkspace(workspace) {
  if (!workspace) return { ok: false, error: 'No workspace to save.' };
  const next = { ...workspace, updatedAt: new Date().toISOString() };
  const result = writeJSON(CURRENT_KEY, next);
  return { ...result, workspace: next };
}

export function clearCurrentWorkspace() {
  const store = storage();
  if (!store) return;
  try {
    store.removeItem(CURRENT_KEY);
  } catch {
    /* ignore */
  }
}

export function getHistory() {
  const value = readJSON(HISTORY_KEY, []);
  return Array.isArray(value) ? value : [];
}

function historyBytes(history) {
  try {
    return JSON.stringify(history).length * 2;
  } catch {
    return 0;
  }
}

function pruneHistory(history, limit, maxBytes) {
  let list = history.slice(0, Math.max(1, limit));
  while (list.length > 1 && historyBytes(list) > maxBytes) {
    list = list.slice(0, -1);
  }
  return list;
}

export function saveSnapshot(workspace, meta = {}) {
  if (!workspace) return { ok: false, error: 'No workspace to snapshot.' };
  const settings = getSettings();
  const history = getHistory();
  const fingerprint = workspaceFingerprint(workspace);
  const latest = history[0];
  if (latest && latest.fingerprint === fingerprint && latest.name === workspace.name) {
    const updated = {
      ...latest,
      savedAt: new Date().toISOString(),
      label: meta.label || latest.label,
      source: meta.source || latest.source,
      score: meta.analysis?.score ?? latest.score ?? null,
      counts: meta.analysis?.counts || latest.counts || null,
    };
    const next = [updated, ...history.slice(1)];
    const result = writeJSON(HISTORY_KEY, next);
    return { ...result, snapshot: updated, deduplicated: true, history: next };
  }
  const snapshot = {
    id: `snap-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`,
    createdAt: new Date().toISOString(),
    savedAt: new Date().toISOString(),
    name: workspace.name,
    label: meta.label || 'Snapshot',
    source: meta.source || 'save',
    fingerprint,
    files: workspace.files.length,
    zones: meta.analysis?.zones ?? meta.zones ?? null,
    score: meta.analysis?.score ?? null,
    counts: meta.analysis?.counts ?? null,
    bytes: new TextEncoder().encode(JSON.stringify(workspace)).length,
    workspace,
  };
  const next = pruneHistory([snapshot, ...history], settings.historyLimit || 100, 4_200_000);
  const result = writeJSON(HISTORY_KEY, next);
  return { ...result, snapshot, history: next };
}

export function getSnapshot(id) {
  return getHistory().find((snapshot) => snapshot.id === id) || null;
}

export function deleteSnapshot(id) {
  const next = getHistory().filter((snapshot) => snapshot.id !== id);
  const result = writeJSON(HISTORY_KEY, next);
  return { ...result, history: next };
}

export function clearHistory() {
  const store = storage();
  if (!store) return { ok: false };
  try {
    store.removeItem(HISTORY_KEY);
    return { ok: true };
  } catch {
    return { ok: false };
  }
}

export function restoreSnapshot(id) {
  const snapshot = getSnapshot(id);
  if (!snapshot?.workspace) return { ok: false, error: 'Snapshot not found.' };
  const current = getCurrentWorkspace();
  if (current) saveSnapshot(current, { label: 'Before restore', source: 'restore' });
  const workspace = {
    ...snapshot.workspace,
    id: snapshot.workspace.id || `ws-${Date.now().toString(36)}`,
    updatedAt: new Date().toISOString(),
  };
  const result = saveCurrentWorkspace(workspace);
  return { ...result, workspace };
}

export function storageStats() {
  const current = getCurrentWorkspace();
  const history = getHistory();
  const bytes = (current ? JSON.stringify(current).length * 2 : 0) + historyBytes(history);
  return {
    currentBytes: current ? JSON.stringify(current).length * 2 : 0,
    historyBytes: historyBytes(history),
    totalBytes: bytes,
    snapshots: history.length,
    limit: getSettings().historyLimit || 100,
    available: Boolean(storage()),
  };
}

export function exportHistoryJson() {
  return `${JSON.stringify({
    format: 'bind-workbench-history',
    version: 1,
    exportedAt: new Date().toISOString(),
    warning: 'History may contain TSIG secrets and private key material copied from imported files. Store it securely.',
    snapshots: getHistory(),
  }, null, 2)}\n`;
}

export function clearAllLocalData() {
  const store = storage();
  if (!store) return;
  for (const key of [CURRENT_KEY, HISTORY_KEY, SETTINGS_KEY]) {
    try {
      store.removeItem(key);
    } catch {
      /* ignore */
    }
  }
}
