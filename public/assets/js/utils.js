/* Small, dependency-free helpers shared by the browser app and Node tests. */

const HTML_ESCAPES = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

export function escapeHTML(value) {
  return String(value ?? '').replace(/[&<>"']/g, (char) => HTML_ESCAPES[char]);
}

export function escapeAttr(value) {
  return escapeHTML(value).replace(/`/g, '&#96;');
}

export function normalizeNewlines(text) {
  return String(text ?? '').replace(/\r\n?/g, '\n');
}

export function lineCount(text) {
  if (!text) return 0;
  const normalized = normalizeNewlines(text);
  return normalized.endsWith('\n') ? normalized.split('\n').length - 1 : normalized.split('\n').length;
}

export function formatBytes(bytes) {
  const value = Number(bytes) || 0;
  if (value < 1024) return `${value} B`;
  const units = ['KiB', 'MiB', 'GiB'];
  let number = value / 1024;
  let index = 0;
  while (number >= 1024 && index < units.length - 1) {
    number /= 1024;
    index += 1;
  }
  return `${number.toFixed(number >= 10 ? 0 : 1)} ${units[index]}`;
}

export function formatNumber(value) {
  return new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 }).format(Number(value) || 0);
}

export function formatDate(value, options = {}) {
  if (!value) return 'unknown';
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    ...options,
  }).format(date);
}

export function formatDateTime(value) {
  if (!value) return 'unknown';
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(date);
}

export function timeAgo(value) {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return 'unknown';
  const seconds = Math.round((date.getTime() - Date.now()) / 1000);
  const abs = Math.abs(seconds);
  if (abs < 45) return seconds >= 0 ? 'in a moment' : 'just now';
  const divisions = [
    [60, 'second'],
    [60, 'minute'],
    [24, 'hour'],
    [7, 'day'],
    [4.35, 'week'],
    [12, 'month'],
    [Infinity, 'year'],
  ];
  let amount = seconds;
  let unit = 'second';
  for (const [size, name] of divisions) {
    unit = name;
    if (Math.abs(amount) < size) break;
    amount /= size;
  }
  const rounded = Math.round(amount);
  const suffix = rounded >= 0 ? 'from now' : 'ago';
  const label = `${Math.abs(rounded)} ${unit}${Math.abs(rounded) === 1 ? '' : 's'}`;
  return `${label} ${suffix}`;
}

export function uid(prefix = 'id') {
  const random = globalThis.crypto?.randomUUID?.() || `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
  return `${prefix}-${random}`;
}

export function debounce(fn, delay = 250) {
  let timer = null;
  const wrapped = (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), delay);
  };
  wrapped.cancel = () => clearTimeout(timer);
  wrapped.flush = (...args) => {
    clearTimeout(timer);
    fn(...args);
  };
  return wrapped;
}

export function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

export function plural(count, singular, pluralForm = `${singular}s`) {
  return `${formatNumber(count)} ${count === 1 ? singular : pluralForm}`;
}

export function parseBindBool(value, fallback = null) {
  const text = String(value ?? '').trim().toLowerCase();
  if (['yes', 'true', 'on', '1'].includes(text)) return true;
  if (['no', 'false', 'off', '0'].includes(text)) return false;
  return fallback;
}

export function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function slugify(value) {
  return String(value ?? '')
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[^\w\s-]/g, '')
    .trim()
    .replace(/[\s_-]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

export function safeJsonParse(text, fallback = null) {
  try {
    return JSON.parse(text);
  } catch {
    return fallback;
  }
}

export function groupBy(items, keyFn) {
  const map = new Map();
  for (const item of items) {
    const key = keyFn(item);
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(item);
  }
  return map;
}

export function sum(items, keyFn = (item) => item) {
  return items.reduce((total, item) => total + (Number(keyFn(item)) || 0), 0);
}

/* ------------------------------------------------------------------ */
/* Browser actions                                                     */
/* ------------------------------------------------------------------ */

export async function copyText(text) {
  const value = String(text ?? '');
  if (globalThis.navigator?.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(value);
      return true;
    } catch {
      /* fall through to the legacy path */
    }
  }
  if (typeof document === 'undefined') return false;
  const area = document.createElement('textarea');
  area.value = value;
  area.setAttribute('readonly', '');
  area.style.position = 'fixed';
  area.style.top = '-1000px';
  document.body.append(area);
  area.select();
  let ok = false;
  try {
    ok = document.execCommand('copy');
  } catch {
    ok = false;
  }
  area.remove();
  return ok;
}

export function downloadBlob(filename, blob) {
  if (typeof document === 'undefined') return;
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = sanitizeArchivePath(filename) || 'download';
  anchor.rel = 'noopener';
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}

export function downloadText(filename, text, mime = 'text/plain;charset=utf-8') {
  downloadBlob(filename, new Blob([String(text ?? '')], { type: mime }));
}

export function readFileText(file) {
  if (file?.text) return file.text();
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result ?? ''));
    reader.onerror = () => reject(reader.error || new Error('Could not read file'));
    reader.readAsText(file);
  });
}

export function readFileBuffer(file) {
  if (file?.arrayBuffer) return file.arrayBuffer();
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(reader.error || new Error('Could not read file'));
    reader.readAsArrayBuffer(file);
  });
}

export function isProbablyText(text) {
  if (typeof text !== 'string') return false;
  if (text.length === 0) return true;
  if (text.includes('\u0000')) return false;
  const sample = text.slice(0, 4000);
  let suspicious = 0;
  for (let index = 0; index < sample.length; index += 1) {
    const code = sample.charCodeAt(index);
    if (code === 9 || code === 10 || code === 13) continue;
    if (code < 32) suspicious += 1;
  }
  return suspicious / Math.max(1, sample.length) < 0.02;
}

/* ------------------------------------------------------------------ */
/* Hashing, base64 and byte helpers                                    */
/* ------------------------------------------------------------------ */

export function concatBytes(...arrays) {
  const list = arrays.filter(Boolean);
  const total = list.reduce((length, array) => length + array.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const array of list) {
    result.set(array, offset);
    offset += array.length;
  }
  return result;
}

export function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex) {
  const clean = String(hex ?? '').replace(/[^0-9a-f]/gi, '');
  if (clean.length % 2 !== 0) throw new Error('Hex input has an odd number of characters');
  const result = new Uint8Array(clean.length / 2);
  for (let index = 0; index < result.length; index += 1) {
    result[index] = Number.parseInt(clean.slice(index * 2, index * 2 + 2), 16);
  }
  return result;
}

export function base64ToBytes(value) {
  const clean = String(value ?? '').replace(/\s+/g, '');
  if (!clean) return new Uint8Array();
  const padded = clean.padEnd(clean.length + ((4 - (clean.length % 4)) % 4), '=');
  let binary;
  try {
    binary = atob(padded);
  } catch {
    throw new Error('Invalid base64 value');
  }
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

export function bytesToBase64(bytes) {
  let binary = '';
  const chunk = 0x8000;
  for (let index = 0; index < bytes.length; index += chunk) {
    binary += String.fromCharCode(...bytes.subarray(index, index + chunk));
  }
  return btoa(binary);
}

export function utf8(text) {
  return new TextEncoder().encode(String(text ?? ''));
}

export function fromUtf8(bytes) {
  return new TextDecoder().decode(bytes);
}

export async function sha256Hex(value) {
  const data = typeof value === 'string' ? utf8(value) : value;
  if (globalThis.crypto?.subtle) {
    try {
      const digest = await crypto.subtle.digest('SHA-256', data);
      return bytesToHex(new Uint8Array(digest));
    } catch {
      /* fall through */
    }
  }
  return null;
}

export function simpleHash(value) {
  const text = typeof value === 'string' ? value : fromUtf8(value);
  let hash = 2166136261;
  for (let index = 0; index < text.length; index += 1) {
    hash ^= text.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(16).padStart(8, '0');
}

/* ------------------------------------------------------------------ */
/* Archive / shell safety                                              */
/* ------------------------------------------------------------------ */

export function sanitizeArchivePath(value) {
  let path = String(value ?? '').replace(/\\/g, '/').trim();
  path = path.replace(/^[a-zA-Z]:/, '').replace(/^\/+/, '');
  const parts = [];
  for (const part of path.split('/')) {
    if (!part || part === '.') continue;
    if (part === '..') continue;
    parts.push(part.replace(/[\u0000-\u001f<>:"|?*]/g, '_'));
  }
  return parts.join('/');
}

export function shellQuote(value) {
  return `'${String(value ?? '').replace(/'/g, `'\\''`)}'`;
}

export function isSafeRelativePath(value) {
  const text = String(value ?? '').replace(/\\/g, '/');
  if (!text || text.startsWith('/') || /^[a-zA-Z]:/.test(text)) return false;
  return !text.split('/').some((part) => part === '..' || part === '');
}

/* ------------------------------------------------------------------ */
/* Display helpers                                                     */
/* ------------------------------------------------------------------ */

export function truncateMiddle(value, length = 42) {
  const text = String(value ?? '');
  if (text.length <= length) return text;
  const keep = Math.floor((length - 1) / 2);
  return `${text.slice(0, keep)}…${text.slice(-keep)}`;
}

export function highlightCodeTokens(text) {
  // Returns escaped HTML with BIND-ish tokens wrapped in spans. The input is
  // escaped first, so this is safe for user-controlled configuration text.
  return escapeHTML(text)
    .replace(/(^|\s)(#|\/\/)(.*)$/g, '$1<span class="tok-comment">$2$3</span>')
    .replace(/(&quot;.*?&quot;)/g, '<span class="tok-string">$1</span>')
    .replace(/\b(yes|no)\b/g, '<span class="tok-bool">$1</span>')
    .replace(/\b(\d+(?:\.\d+){3})\b/g, '<span class="tok-ip">$1</span>')
    .replace(/\b([A-Z][A-Z0-9]{1,9})\b/g, '<span class="tok-type">$1</span>');
}
