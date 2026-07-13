import { useCallback, useEffect, useState } from 'react';

// Theme manager: light (default) / dark / system. The authoritative store is
// chrome.storage.local["theme"]; a localStorage mirror lets us apply the theme
// synchronously at import time so users don't see a theme flash
// before chrome.storage (async) resolves.

const STORAGE_KEY = 'theme';
const MIRROR_KEY = 'sectest-theme';
export const THEME_MODES = ['dark', 'light', 'system'];

function prefersDark() {
  try {
    return !!(window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
  } catch (_) {
    return true; // default to dark when matchMedia is unavailable
  }
}

// Resolve a mode to the concrete theme actually applied to the DOM.
export function resolveTheme(mode) {
  if (mode === 'system') return prefersDark() ? 'dark' : 'light';
  return mode === 'light' ? 'light' : 'dark';
}

function applyResolved(resolved) {
  if (typeof document !== 'undefined' && document.documentElement) {
    document.documentElement.setAttribute('data-theme', resolved);
  }
}

function readMirror() {
  try {
    return localStorage.getItem(MIRROR_KEY);
  } catch (_) {
    return null;
  }
}

function writeMirror(mode) {
  try {
    localStorage.setItem(MIRROR_KEY, mode);
  } catch (_) {}
}

// Seed + apply synchronously at module load (before first paint).
const initialMode = (() => {
  const m = readMirror();
  return THEME_MODES.includes(m) ? m : 'light';
})();
applyResolved(resolveTheme(initialMode));

export function useTheme() {
  const [theme, setThemeState] = useState(initialMode);

  // Reconcile with chrome.storage.local (authoritative) once, on mount.
  useEffect(() => {
    try {
      chrome.storage.local.get([STORAGE_KEY], (res) => {
        const stored = res && res[STORAGE_KEY];
        if (THEME_MODES.includes(stored)) {
          setThemeState(stored);
          writeMirror(stored);
        }
      });
    } catch (_) {}
  }, []);

  // Apply on every change; for "system", also follow live OS changes.
  useEffect(() => {
    applyResolved(resolveTheme(theme));
    if (theme !== 'system') return undefined;
    let mql;
    try {
      mql = window.matchMedia('(prefers-color-scheme: dark)');
    } catch (_) {
      return undefined;
    }
    const onChange = () => applyResolved(resolveTheme('system'));
    if (mql.addEventListener) mql.addEventListener('change', onChange);
    else if (mql.addListener) mql.addListener(onChange);
    return () => {
      if (mql.removeEventListener) mql.removeEventListener('change', onChange);
      else if (mql.removeListener) mql.removeListener(onChange);
    };
  }, [theme]);

  const setTheme = useCallback((next) => {
    const mode = THEME_MODES.includes(next) ? next : 'dark';
    setThemeState(mode);
    writeMirror(mode);
    try {
      chrome.storage.local.set({ [STORAGE_KEY]: mode });
    } catch (_) {}
  }, []);

  const cycle = useCallback(() => {
    setThemeState((cur) => {
      const mode = THEME_MODES[(THEME_MODES.indexOf(cur) + 1) % THEME_MODES.length];
      writeMirror(mode);
      try {
        chrome.storage.local.set({ [STORAGE_KEY]: mode });
      } catch (_) {}
      return mode;
    });
  }, []);

  return { theme, resolved: resolveTheme(theme), setTheme, cycle };
}

export default useTheme;
