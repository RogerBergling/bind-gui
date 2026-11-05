/* Shared import controls: file/folder pickers, drag-and-drop and samples. */

import { saveCurrentWorkspace, saveSnapshot } from '../storage.js';
import { workspaceFromFileList, workspaceFromSample } from '../dns/import.js';
import { sampleById } from '../data/samples.js';
import { toast, openModal } from '../ui.js';
import { icon } from '../ui.js';
import { escapeHTML } from '../utils.js';

const UPLOAD_UNLOCK_KEY = 'bind-workbench:upload-unlocked';
let uploadStatusPromise = null;
let uploadUnlockPromise = null;
let uploadUnlockedThisPage = false;
let uploadAuthRequired = false;

export async function getUploadStatus() {
  if (!uploadStatusPromise) {
    uploadStatusPromise = fetch('/api/upload-status', { cache: 'no-store', credentials: 'same-origin' })
      .then((response) => (response.ok ? response.json() : { required: false }))
      .catch(() => ({ required: false }));
  }
  return uploadStatusPromise;
}

function hasUploadUnlock() {
  if (uploadUnlockedThisPage) return true;
  try {
    return sessionStorage.getItem(UPLOAD_UNLOCK_KEY) === '1';
  } catch {
    return false;
  }
}

function rememberUploadUnlock() {
  uploadUnlockedThisPage = true;
  try {
    sessionStorage.setItem(UPLOAD_UNLOCK_KEY, '1');
  } catch {
    /* Session storage may be disabled; keep the in-memory unlock for this page. */
  }
}

export function clearUploadUnlock() {
  uploadUnlockedThisPage = false;
  try {
    sessionStorage.removeItem(UPLOAD_UNLOCK_KEY);
  } catch {
    /* ignore */
  }
}

async function verifyUploadPassword(password) {
  try {
    const response = await fetch('/api/upload-auth', {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { 'X-Bind-Upload-Password': password },
    });
    let data = {};
    try {
      data = await response.json();
    } catch {
      /* keep the status-code message */
    }
    if (response.ok && data.ok) return { ok: true };
    if (response.status === 429) return { ok: false, error: 'Too many attempts. Wait a minute and try again.' };
    if (response.status === 401) return { ok: false, error: 'Invalid import password.' };
    return { ok: false, error: data.error || `Import unlock failed (HTTP ${response.status}).` };
  } catch {
    return { ok: false, error: 'Could not reach the server to verify the import password.' };
  }
}

function uploadGatePanel(status) {
  if (hasUploadUnlock()) {
    return `<div class="upload-gate-panel unlocked">
      <div class="upload-gate-icon">${icon('check', 17)}</div>
      <div class="upload-gate-copy"><strong>Import unlocked for this tab</strong><span>The password was verified. Lock the session or close the tab to require it again.</span></div>
    </div>`;
  }
  return `<div class="upload-gate-panel">
    <div class="upload-gate-icon">${icon('lock', 17)}</div>
    <div class="upload-gate-copy">
      <strong>Import password required</strong>
      <span>${status.separatePassword ? 'This server requires a dedicated import password.' : 'This server uses the app password for the import check.'} Verified server-side; not stored in the browser.</span>
    </div>
    <div class="upload-gate-control">
      <input class="upload-gate-input" type="password" autocomplete="current-password" spellcheck="false" placeholder="Import password" aria-label="Import password">
      <button class="btn btn-primary btn-sm" type="button" data-upload-unlock>${icon('lock', 14)} Unlock</button>
    </div>
    <div class="upload-gate-error" role="alert" hidden></div>
  </div>`;
}

function refreshUploadGatePanels() {
  for (const panel of document.querySelectorAll('[data-upload-gate]')) {
    if (!panel.dataset.required || panel.dataset.required !== 'true') continue;
    panel.innerHTML = uploadGatePanel(JSON.parse(panel.dataset.gateStatus || '{}'));
    wireUploadGatePanel(panel);
  }
}

function wireUploadGatePanel(panel) {
  const input = panel.querySelector('.upload-gate-input');
  const button = panel.querySelector('[data-upload-unlock]');
  const error = panel.querySelector('.upload-gate-error');
  if (!input || !button) return;
  const submit = async () => {
    const password = input.value;
    if (!password) {
      error.textContent = 'Enter the import password.';
      error.hidden = false;
      input.focus();
      return;
    }
    button.disabled = true;
    button.textContent = 'Checking…';
    const result = await verifyUploadPassword(password);
    button.disabled = false;
    button.innerHTML = `${icon('lock', 14)} Unlock`;
    if (result.ok) {
      rememberUploadUnlock();
      refreshUploadGatePanels();
      toast('Import unlocked for this tab.', 'ok');
    } else {
      error.textContent = result.error;
      error.hidden = false;
      input.select();
    }
  };
  button.addEventListener('click', submit);
  input.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      submit();
    }
  });
}

export async function mountUploadGate(root = document) {
  const panels = Array.from(root.querySelectorAll('[data-upload-gate]'));
  if (!panels.length) return;
  const status = await getUploadStatus();
  uploadAuthRequired = Boolean(status?.required);
  for (const panel of panels) {
    panel.dataset.required = String(Boolean(status?.required));
    panel.dataset.gateStatus = JSON.stringify(status || {});
    if (!status?.required) {
      panel.hidden = true;
      panel.innerHTML = '';
      continue;
    }
    panel.hidden = false;
    panel.innerHTML = uploadGatePanel(status);
    wireUploadGatePanel(panel);
  }
}

/**
 * Ask for the server-side import password before any local file is read.
 * The password is sent only to /api/upload-auth and is not stored.
 */
export async function ensureUploadUnlocked() {
  if (hasUploadUnlock()) return true;
  const status = await getUploadStatus();
  if (!status?.required) return true;
  if (uploadUnlockPromise) return uploadUnlockPromise;

  uploadUnlockPromise = new Promise((resolve) => {
    let settled = false;
    const finish = (value, close) => {
      if (settled) return;
      settled = true;
      if (close) close();
      resolve(value);
      uploadUnlockPromise = null;
    };
    const { dialog, close } = openModal({
      title: 'Import password required',
      lede: 'This deployment requires a password before configuration files can be read. The check is server-side; the password is not stored in the browser.',
      body: `<div class="form-grid">
        <label class="field span-2"><span>Import password</span><input id="upload-auth-password" type="password" autocomplete="current-password" spellcheck="false" autofocus><small>${status.separatePassword ? 'Protects only the import action.' : 'The server is using the app password for this import check.'}</small></label>
      </div>
      <div class="login-error" id="upload-auth-error" role="alert" hidden></div>`,
      actions: `<button class="btn btn-ghost" type="button" data-modal-close>Cancel</button><button class="btn btn-primary" type="button" id="upload-auth-submit">${icon('lock', 15)} Unlock import</button>`,
      onMount: (mountedDialog) => {
        const input = mountedDialog.querySelector('#upload-auth-password');
        const errorNode = mountedDialog.querySelector('#upload-auth-error');
        const submit = mountedDialog.querySelector('#upload-auth-submit');
        const showError = (message) => {
          errorNode.textContent = message;
          errorNode.hidden = false;
        };
        const attempt = async () => {
          const password = input.value;
          if (!password) {
            showError('Enter the import password.');
            input.focus();
            return;
          }
          errorNode.hidden = true;
          submit.disabled = true;
          submit.textContent = 'Checking…';
          const result = await verifyUploadPassword(password);
          if (result.ok) {
            rememberUploadUnlock();
            refreshUploadGatePanels();
            toast('Import unlocked for this tab.', 'ok');
            finish(true, close);
            return;
          }
          showError(result.error);
          input.select();
          submit.disabled = false;
          submit.textContent = 'Unlock import';
        };
        submit.addEventListener('click', attempt);
        input.addEventListener('keydown', (event) => {
          if (event.key === 'Enter') {
            event.preventDefault();
            attempt();
          }
        });
        setTimeout(() => input.focus(), 50);
        mountedDialog.addEventListener('close', () => finish(false));
      },
    });
    void dialog;
    void close;
  });
  return uploadUnlockPromise;
}

async function collectEntry(entry, prefix, files) {
  if (!entry) return;
  if (entry.isFile) {
    const file = await new Promise((resolve, reject) => entry.file(resolve, reject));
    if (file) {
      try {
        Object.defineProperty(file, 'webkitRelativePath', { value: `${prefix}${file.name}`, configurable: true });
      } catch {
        /* Some browsers make File properties non-configurable; the importer falls back to name. */
      }
      files.push(file);
    }
    return;
  }
  if (entry.isDirectory) {
    const reader = entry.createReader();
    const entries = [];
    await new Promise((resolve) => {
      const readBatch = () => {
        reader.readEntries((batch) => {
          if (!batch.length) {
            resolve();
            return;
          }
          entries.push(...batch);
          readBatch();
        }, () => resolve());
      };
      readBatch();
    });
    for (const child of entries) await collectEntry(child, `${prefix}${entry.name}/`, files);
  }
}

async function filesFromDataTransfer(dataTransfer) {
  const files = [];
  const items = Array.from(dataTransfer.items || []);
  if (items.length && items.some((item) => item.webkitGetAsEntry)) {
    for (const item of items) {
      const entry = item.webkitGetAsEntry();
      if (entry) await collectEntry(entry, '', files);
    }
  }
  if (!files.length) files.push(...Array.from(dataTransfer.files || []));
  return files;
}

async function handleImport(files, options = {}) {
  if (!files?.length) return null;
  try {
    const { workspace, warnings } = await workspaceFromFileList(files);
    saveCurrentWorkspace(workspace);
    saveSnapshot(workspace, { label: 'Imported workspace', source: 'import' });
    if (warnings.length) {
      openModal({
        title: 'Imported with notes',
        lede: `${workspace.files.length} file(s) loaded. Some items were skipped or adjusted.`,
        body: `<ul class="modal-details">${warnings.map((warning) => `<li>${escapeHTML(warning)}</li>`).join('')}</ul>`,
      });
    }
    toast(`Imported ${workspace.files.length} file(s).`, 'ok');
    options.onImported?.(workspace);
    if (options.navigate !== false && location.hash !== '#/workbench') location.hash = '#/workbench';
    else window.dispatchEvent(new Event('workbench:reload'));
    return workspace;
  } catch (error) {
    toast(error?.message || 'The import failed.', 'danger');
    openModal({
      title: 'Could not import',
      body: `<p>${escapeHTML(error?.message || 'Unknown import error.')}</p>
      <div class="callout info">${icon('info', 18)}<div>Supported inputs are ordinary text files, a folder, a ZIP bundle, or a BIND Workbench workspace JSON file. Binary files and archives larger than the browser limits are skipped.</div></div>`,
    });
    return null;
  }
}

export function loadSample(sampleId, onImported = null) {
  const sample = sampleById(sampleId);
  if (!sample) {
    toast('Sample not found.', 'danger');
    return null;
  }
  const workspace = workspaceFromSample(sample);
  saveCurrentWorkspace(workspace);
  saveSnapshot(workspace, { label: `Loaded ${sample.title}`, source: 'sample' });
  toast(`${sample.title} loaded.`, 'ok');
  if (onImported) onImported(workspace);
  if (location.hash !== '#/workbench') location.hash = '#/workbench';
  else window.dispatchEvent(new Event('workbench:reload'));
  return workspace;
}

function focusUploadGate(root) {
  const gate = root.querySelector('[data-upload-gate]');
  if (!gate || gate.hidden) return false;
  gate.scrollIntoView({ behavior: 'smooth', block: 'center' });
  const input = gate.querySelector('.upload-gate-input');
  if (input) setTimeout(() => input.focus(), 150);
  toast('Enter the import password before choosing files.', 'warn');
  return true;
}

function importBlocked(root) {
  return uploadAuthRequired && !hasUploadUnlock() && focusUploadGate(root);
}

export function wireImportControls(root, options = {}) {
  let fileInput = root.querySelector('#import-file-input');
  let folderInput = root.querySelector('#import-folder-input');
  if (!fileInput) {
    fileInput = document.createElement('input');
    fileInput.type = 'file';
    fileInput.id = 'import-file-input';
    fileInput.multiple = true;
    fileInput.accept = '.conf,.cfg,.zone,.db,.rev,.hosts,.signed,.nzf,.txt,.json,.zip,.key,.private';
    fileInput.hidden = true;
    fileInput.addEventListener('change', async () => {
      const files = Array.from(fileInput.files || []);
      fileInput.value = '';
      if (!(await ensureUploadUnlocked())) return;
      await handleImport(files, options);
    });
    root.append(fileInput);
  }
  if (!folderInput) {
    folderInput = document.createElement('input');
    folderInput.type = 'file';
    folderInput.id = 'import-folder-input';
    folderInput.multiple = true;
    folderInput.webkitdirectory = true;
    folderInput.hidden = true;
    folderInput.addEventListener('change', async () => {
      const files = Array.from(folderInput.files || []);
      folderInput.value = '';
      if (!(await ensureUploadUnlocked())) return;
      await handleImport(files, options);
    });
    root.append(folderInput);
  }

  root.querySelectorAll('[data-import-files]').forEach((button) => {
    if (button.dataset.wired === 'true') return;
    button.dataset.wired = 'true';
    button.addEventListener('click', () => {
      if (importBlocked(root)) return;
      fileInput.click();
    });
  });
  root.querySelectorAll('[data-import-folder]').forEach((button) => {
    if (button.dataset.wired === 'true') return;
    button.dataset.wired = 'true';
    button.addEventListener('click', () => {
      if (importBlocked(root)) return;
      folderInput.click();
    });
  });
  root.querySelectorAll('[data-sample-id]').forEach((button) => {
    if (button.dataset.wired === 'true') return;
    button.dataset.wired = 'true';
    button.addEventListener('click', () => loadSample(button.dataset.sampleId, options.onImported));
  });

  root.querySelectorAll('[data-dropzone]').forEach((zone) => {
    if (zone.dataset.wired === 'true') return;
    zone.dataset.wired = 'true';
    zone.addEventListener('click', () => {
      if (importBlocked(root)) return;
      fileInput.click();
    });
    zone.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        if (importBlocked(root)) return;
        fileInput.click();
      }
    });
    const stop = (event) => {
      event.preventDefault();
      event.stopPropagation();
    };
    zone.addEventListener('dragover', (event) => {
      stop(event);
      zone.classList.add('dragging');
    });
    zone.addEventListener('dragleave', (event) => {
      stop(event);
      zone.classList.remove('dragging');
    });
    zone.addEventListener('drop', async (event) => {
      stop(event);
      zone.classList.remove('dragging');
      if (importBlocked(root)) return;
      if (!(await ensureUploadUnlocked())) return;
      const files = await filesFromDataTransfer(event.dataTransfer);
      if (files.length) await handleImport(files, options);
    });
  });

  mountUploadGate(root);
  return { fileInput, folderInput, importFiles: (files) => handleImport(files, options) };
}

export { handleImport };
