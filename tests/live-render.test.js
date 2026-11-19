import test from 'node:test';
import assert from 'node:assert/strict';

import { renderLive } from '../public/assets/js/pages/live.js';

function fakeElement(id) {
  return {
    id,
    value: '',
    hidden: false,
    textContent: '',
    innerHTML: '',
    dataset: {},
    classList: { toggle() {}, add() {}, remove() {} },
    addEventListener() {},
    setAttribute() {},
    querySelector() { return null; },
    querySelectorAll() { return []; },
  };
}

function fakeView() {
  const cache = new Map();
  return {
    _html: '',
    set innerHTML(value) { this._html = value; },
    get innerHTML() { return this._html; },
    querySelector(selector) {
      if (!selector.startsWith('#')) return null;
      const id = selector.slice(1);
      if (!this._html.includes(`id="${id}"`)) return null;
      if (!cache.has(id)) cache.set(id, fakeElement(id));
      return cache.get(id);
    },
    querySelectorAll() { return []; },
  };
}

test('renders Live DNS without an imported workspace', async () => {
  const originalStorage = Object.getOwnPropertyDescriptor(globalThis, 'localStorage');
  Object.defineProperty(globalThis, 'localStorage', {
    configurable: true,
    value: {
      getItem() { return null; },
      setItem() {},
      removeItem() {},
    },
  });
  try {
    const view = fakeView();
    await renderLive(view, new URLSearchParams(''));
    assert.match(view.innerHTML, /Import a zone first/);
    assert.match(view.innerHTML, /Custom resolvers/);
  } finally {
    if (originalStorage) Object.defineProperty(globalThis, 'localStorage', originalStorage);
    else delete globalThis.localStorage;
  }
});
