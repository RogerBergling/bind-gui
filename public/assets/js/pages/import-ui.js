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
            if (response.ok && data.ok) {
              rememberUploadUnlock();
              toast('Import unlocked for this tab.', 'ok');
              finish(true, close);
              return;
            }
            if (response.status === 429) showError('Too many attempts. Wait a minute and try again.');
            else if (response.status === 401) showError('Invalid import password.');
            else showError(data.error || `Import unlock failed (HTTP ${response.status}).`);
            input.select();
          } catch {
            showError('Could not reach the server to verify the import password.');
          } finally {
            submit.disabled = false;
            submit.textContent = 'Unlock import';
          }
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
    button.addEventListener('click', () => fileInput.click());
  });
  root.querySelectorAll('[data-import-folder]').forEach((button) => {
    if (button.dataset.wired === 'true') return;
    button.dataset.wired = 'true';
    button.addEventListener('click', () => folderInput.click());
  });
  root.querySelectorAll('[data-sample-id]').forEach((button) => {
    if (button.dataset.wired === 'true') return;
    button.dataset.wired = 'true';
    button.addEventListener('click', () => loadSample(button.dataset.sampleId, options.onImported));
  });

  root.querySelectorAll('[data-dropzone]').forEach((zone) => {
    if (zone.dataset.wired === 'true') return;
    zone.dataset.wired = 'true';
    zone.addEventListener('click', () => fileInput.click());
    zone.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
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
      if (!(await ensureUploadUnlocked())) return;
      const files = await filesFromDataTransfer(event.dataTransfer);
      if (files.length) await handleImport(files, options);
    });
  });

  return { fileInput, folderInput, importFiles: (files) => handleImport(files, options) };
}

export { handleImport };
