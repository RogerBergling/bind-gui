/* Password gate for password-protected deployments. */

const form = document.getElementById('login-form');
const input = document.getElementById('login-password');
const submit = document.getElementById('login-submit');
const errorNode = document.getElementById('login-error');

function applySavedTheme() {
  try {
    const settings = JSON.parse(localStorage.getItem('bind-workbench:v1:settings') || '{}');
    if (settings.theme === 'light' || settings.theme === 'dark') {
      document.documentElement.dataset.theme = settings.theme;
      document.documentElement.style.colorScheme = settings.theme;
    }
  } catch {
    /* localStorage may be unavailable; keep the default theme. */
  }
}

function showError(message) {
  errorNode.textContent = message;
  errorNode.hidden = false;
}

function hideError() {
  errorNode.hidden = true;
  errorNode.textContent = '';
}

async function checkStatus() {
  try {
    const response = await fetch('/api/auth-status', { cache: 'no-store', credentials: 'same-origin' });
    if (!response.ok) return;
    const status = await response.json();
    if (!status.required || status.authenticated) location.replace('/');
  } catch {
    showError('Could not reach the server. Check that the container or start.py is running.');
  }
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  hideError();
  const password = input.value;
  if (!password) {
    showError('Enter the password.');
    input.focus();
    return;
  }
  submit.disabled = true;
  submit.textContent = 'Checking…';
  try {
    const response = await fetch('/api/login', {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password }),
    });
    let data = {};
    try {
      data = await response.json();
    } catch {
      /* keep the status-code message */
    }
    if (response.ok && data.ok) {
      location.reload();
      return;
    }
    if (response.status === 429) showError('Too many attempts. Wait a minute and try again.');
    else if (response.status === 401) showError('Invalid password.');
    else showError(data.error || `Login failed (HTTP ${response.status}).`);
    input.select();
  } catch {
    showError('Could not reach the server. Check the container, reverse proxy and HTTPS configuration.');
  } finally {
    submit.disabled = false;
    submit.textContent = 'Unlock BIND Workbench';
  }
});

applySavedTheme();
checkStatus();
