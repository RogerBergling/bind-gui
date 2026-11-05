/* Build metadata and a small live clock for the shell and footer. */

let buildInfoPromise = null;
let clockTimer = null;

export function loadBuildInfo() {
  if (!buildInfoPromise) {
    buildInfoPromise = fetch('/version.json', { cache: 'no-store', credentials: 'omit' })
      .then((response) => (response.ok ? response.json() : null))
      .then((data) => ({
        version: data?.version || 'dev',
        imageTag: data?.imageTag || 'local',
        commit: data?.commit || 'local',
        buildDate: data?.buildDate || null,
      }))
      .catch(() => ({ version: 'dev', imageTag: 'local', commit: 'local', buildDate: null }));
  }
  return buildInfoPromise;
}

function formatClock(date = new Date()) {
  return new Intl.DateTimeFormat(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    timeZoneName: 'short',
  }).format(date);
}

function applyClock(root) {
  const nodes = root.querySelectorAll?.('[data-live-clock]') || [];
  for (const node of nodes) {
    node.textContent = formatClock();
    node.setAttribute('datetime', new Date().toISOString());
  }
}

export function applyBuildInfo(root = document, info) {
  const data = info || { version: 'dev', imageTag: 'local', commit: 'local', buildDate: null };
  for (const node of root.querySelectorAll?.('[data-app-version]') || []) node.textContent = data.version;
  for (const node of root.querySelectorAll?.('[data-image-tag]') || []) node.textContent = data.imageTag;
  for (const node of root.querySelectorAll?.('[data-commit]') || []) node.textContent = data.commit;
  for (const node of root.querySelectorAll?.('[data-commit-link]') || []) {
    if (data.commit && data.commit !== 'local') {
      node.href = `https://github.com/RogerBergling/bind-gui/commit/${encodeURIComponent(data.commit)}`;
      node.rel = 'noopener noreferrer';
      node.target = '_blank';
    } else {
      node.removeAttribute('href');
    }
  }
  for (const node of root.querySelectorAll?.('[data-build-date]') || []) {
    node.textContent = data.buildDate ? new Date(data.buildDate).toLocaleString() : 'local build';
    if (data.buildDate) node.setAttribute('datetime', data.buildDate);
  }
  applyClock(root);
  if (!clockTimer && typeof window !== 'undefined') {
    clockTimer = window.setInterval(() => applyClock(document), 1000);
    window.addEventListener('pagehide', () => {
      clearInterval(clockTimer);
      clockTimer = null;
    }, { once: true });
  }
}
