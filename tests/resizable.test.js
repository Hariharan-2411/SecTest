import { describe, it, expect, jest, beforeEach } from '@jest/globals';
import React from 'react';
import { render, fireEvent, act } from '@testing-library/react';
import { useResizable } from '../src/hooks/useResizable';

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

function Harness() {
  const { onResizeStart } = useResizable();
  return <div data-testid="handle" onPointerDown={onResizeStart} />;
}

const wVar = () => document.documentElement.style.getPropertyValue('--popup-w');
const hVar = () => document.documentElement.style.getPropertyValue('--popup-h');

describe('useResizable', () => {
  beforeEach(() => {
    document.documentElement.removeAttribute('style');
  });

  it('applies the default size vars on mount', () => {
    setupChrome({});
    act(() => render(<Harness />));
    expect(wVar()).toBe('600px');
    expect(hVar()).toBe('560px');
  });

  it('drag grows the size, clamped to the popup max, and persists on release', () => {
    const store = setupChrome({});
    const { getByTestId } = render(<Harness />);

    act(() => {
      fireEvent(
        getByTestId('handle'),
        new MouseEvent('pointerdown', { clientX: 100, clientY: 100, bubbles: true })
      );
    });
    // Drag far past the max → should clamp to 780 x 590.
    act(() => {
      window.dispatchEvent(new MouseEvent('pointermove', { clientX: 600, clientY: 600 }));
    });
    expect(wVar()).toBe('780px');
    expect(hVar()).toBe('590px');

    act(() => {
      window.dispatchEvent(new MouseEvent('pointerup'));
    });
    expect(chrome.storage.local.set).toHaveBeenCalledWith({ popupSize: { width: 780, height: 590 } });
    expect(store.popupSize).toEqual({ width: 780, height: 590 });
  });

  it('hydrates a persisted size (clamped) on mount', () => {
    setupChrome({ popupSize: { width: 9999, height: 100 } });
    act(() => render(<Harness />));
    // width clamps to 780, height clamps up to the 420 minimum.
    expect(wVar()).toBe('780px');
    expect(hVar()).toBe('420px');
  });
});
