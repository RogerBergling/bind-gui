/*
 * Build metadata, a live 24-hour clock and consistent build formatting.
 * Build metadata is baked into /version.json by the Docker build and is also
 * available when running locally. Fetch only from the same origin.
 */

const FALLBACK = {
  version: 'dev',
  imageTag: 'local',
  commit: 'local',
  buildDate: null,
};

let buildInfoPromise = null;
let clockTimer = null;

function pad(value) {
  return String(value).padStart(2, '0');
}

function normalize(value) {
  if (!value || typeof value !== 'object') return { ...FALLBACK };
  return {
    version: String(value.version || FALLBACK.version),
    imageTag: String(value.imageTag || FALLBACK.imageTag),
    commit: String(value.commit || FALLBACK.commit),
    buildDate: value.buildDate || null,
  };
}

export function loadBuildInfo() {
  if (!buildInfoPromise) {
    buildInfoPromise = fetch('/version.json', { cache: 'no-store', credentials: 'same-origin' })
      .then((response) => (response.ok ? response.json() : null))
      .then(normalize)
      .catch(() => ({ ...FALLBACK }));
  }
  return buildInfoPromise;
}

export function shortCommit(commit) {
  const value = String(commit || 'local');
  return value === 'local' ? 'local' : value.slice(0, 12);
}

/** Build number is the UTC build timestamp as YYYYMMDD.HHMM. */
export function buildNumber(value) {
  if (!value) return 'local';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return `${date.getUTCFullYear()}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}.${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}`;
}

export function formatBuildDate(value) {
  if (!value) return 'local build';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())} UTC`;
}

/** Local clock, forced to a 24-hour cycle in every locale. */
export function formatClock(date = new Date()) {
  return new Intl.DateTimeFormat(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
    timeZoneName: 'short',
  }).format(date);
}

function applyClock(root = document) {
  const now = new Date();
  const text = formatClock(now);
  root.querySelectorAll?.('[data-live-clock], [data-live-clock-stamp]').forEach((node) => {
    node.textContent = text;
    node.setAttribute('datetime', now.toISOString());
  });
}

function startClockTicker() {
  if (clockTimer || typeof window === 'undefined') return;
  clockTimer = window.setInterval(() => applyClock(document), 1000);
  window.addEventListener('pagehide', () => {
    window.clearInterval(clockTimer);
    clockTimer = null;
  }, { once: true });
}

export function applyBuildInfo(root = document, info) {
  const data = normalize(info);
  const set = (selector, value) => {
    root.querySelectorAll?.(selector).forEach((node) => {
      node.textContent = value;
    });
  };

  set('[data-app-version]', data.version);
  set('[data-build-number]', buildNumber(data.buildDate));
  set('[data-image-tag]', data.imageTag);
  set('[data-commit]', shortCommit(data.commit));
  set('[data-build-date]', formatBuildDate(data.buildDate));

  root.querySelectorAll?.('[data-commit-link]').forEach((node) => {
    if (/^[0-9a-f]{7,40}$/i.test(data.commit)) {
      node.href = `https://github.com/RogerBergling/bind-gui/commit/${encodeURIComponent(data.commit)}`;
      node.rel = 'noopener noreferrer';
      node.target = '_blank';
    } else {
      node.removeAttribute('href');
    }
  });

  applyClock(root);
  startClockTicker();
}
