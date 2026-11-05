/* Optional server-side password session controls. */

import { icon } from './ui.js';

export async function initAuth() {
  try {
    const response = await fetch('/api/auth-status', { cache: 'no-store', credentials: 'same-origin' });
    if (!response.ok) return;
    const status = await response.json();
    if (!status.required) return;
    if (!status.authenticated) {
      location.replace('/login');
      return;
    }
    const tools = document.querySelector('.topbar-tools');
    if (!tools || tools.querySelector('[data-auth-lock]')) return;
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'btn btn-icon auth-lock';
    button.dataset.authLock = 'true';
    button.title = 'Lock this session';
    button.setAttribute('aria-label', 'Lock this session');
    button.innerHTML = icon('lock', 18);
    button.addEventListener('click', async () => {
      button.disabled = true;
      try {
        await fetch('/api/logout', { method: 'POST', credentials: 'same-origin', cache: 'no-store' });
      } catch {
        /* Clear the cookie on the next request anyway; still navigate to login. */
      }
      location.replace('/login');
    });
    tools.prepend(button);
  } catch {
    /* Auth is optional; a static deployment without an API simply has no lock. */
  }
}
