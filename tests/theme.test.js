import { describe, it, expect, jest, beforeEach } from '@jest/globals';
import '@testing-library/jest-dom';
import React from 'react';
import { render, screen, act } from '@testing-library/react';
import { useTheme } from '../src/hooks/useTheme';

// Mock the chrome.storage.local surface the hook uses.
function setupChrome(initial = {}) {
  const store = { ...initial };
  global.chrome = {
    storage: {
      local: {
        get: jest.fn((keys, cb) => cb(store)),
        set: jest.fn((obj, cb) => {
          Object.assign(store, obj);
          if (cb) cb();
        }),
      },
    },
  };
  return store;
}

function setupMatchMedia(dark) {
  window.matchMedia = jest.fn().mockImplementation((query) => ({
    matches: dark,
    media: query,
    addEventListener: jest.fn(),
    removeEventListener: jest.fn(),
    addListener: jest.fn(),
    removeListener: jest.fn(),
  }));
}

function Harness() {
  const { theme, resolved, cycle, setTheme } = useTheme();
  return (
    <div>
      <span data-testid="theme">{theme}</span>
      <span data-testid="resolved">{resolved}</span>
      <button onClick={cycle}>cycle</button>
      <button onClick={() => setTheme('light')}>light</button>
      <button onClick={() => setTheme('system')}>system</button>
    </div>
  );
}

const dataTheme = () => document.documentElement.getAttribute('data-theme');

describe('useTheme', () => {
  beforeEach(() => {
    try {
      localStorage.clear();
    } catch (_) {}
    document.documentElement.removeAttribute('data-theme');
    setupMatchMedia(false);
  });

  it('defaults to dark and applies data-theme="dark"', () => {
    setupChrome({});
    act(() => {
      render(<Harness />);
    });
    expect(screen.getByTestId('theme').textContent).toBe('dark');
    expect(dataTheme()).toBe('dark');
  });

  it('setTheme("light") applies light and persists to chrome.storage', () => {
    const store = setupChrome({});
    act(() => render(<Harness />));
    act(() => screen.getByText('light').click());
    expect(dataTheme()).toBe('light');
    expect(chrome.storage.local.set).toHaveBeenCalledWith({ theme: 'light' });
    expect(store.theme).toBe('light');
  });

  it('"system" mode resolves to light when the OS prefers light', () => {
    setupMatchMedia(false); // prefers light
    setupChrome({});
    act(() => render(<Harness />));
    act(() => screen.getByText('system').click());
    expect(screen.getByTestId('resolved').textContent).toBe('light');
    expect(dataTheme()).toBe('light');
  });

  it('"system" mode resolves to dark when the OS prefers dark', () => {
    setupMatchMedia(true); // prefers dark
    setupChrome({});
    act(() => render(<Harness />));
    act(() => screen.getByText('system').click());
    expect(screen.getByTestId('resolved').textContent).toBe('dark');
    expect(dataTheme()).toBe('dark');
  });

  it('hydrates the stored mode from chrome.storage on mount', () => {
    setupChrome({ theme: 'light' });
    act(() => render(<Harness />));
    expect(screen.getByTestId('theme').textContent).toBe('light');
    expect(dataTheme()).toBe('light');
  });
});
