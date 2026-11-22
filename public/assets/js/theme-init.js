/* Apply the saved or server-configured theme before first paint.
   /theme.js supplies window.__APP_THEME__ from the APP_THEME environment
   variable. A visitor's explicit choice in the theme toggle wins. */
(() => {
  const root = document.documentElement;
  const KEY = 'bind-workbench:v1:settings';
  let saved = null;

  try {
    const raw = localStorage.getItem(KEY);
    if (raw) {
      const settings = JSON.parse(raw);
      if (settings && (settings.theme === 'light' || settings.theme === 'dark')) {
        saved = settings.theme;
      }
    }
  } catch {
    /* Storage can be unavailable in hardened browser contexts. */
  }

  let theme = saved;
  if (!theme) {
    const configured = window.__APP_THEME__;
    if (configured === 'light' || configured === 'dark') {
      theme = configured;
    } else if (configured === 'system') {
      theme = window.matchMedia?.('(prefers-color-scheme: light)')?.matches ? 'light' : 'dark';
    } else {
      theme = 'dark';
    }
  }

  root.dataset.theme = theme;
  root.style.colorScheme = theme;
})();
