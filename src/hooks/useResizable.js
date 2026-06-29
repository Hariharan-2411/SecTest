import { useCallback, useEffect, useRef, useState } from 'react';

// Make the popup user-resizable via a drag handle. Chrome caps popup windows at
// ~800x600, so we clamp within that. The chosen size is written to CSS vars
// (--popup-w / --popup-h, consumed by html/body/.sectest-container) and
// persisted to chrome.storage.local.

const KEY = 'popupSize';
const MIN_W = 360;
const MAX_W = 780;
const MIN_H = 420;
const MAX_H = 590;
const DEFAULT = { width: 600, height: 560 };

const clamp = (v, min, max) => Math.max(min, Math.min(max, v));

function applyVars({ width, height }) {
  if (typeof document === 'undefined' || !document.documentElement) return;
  document.documentElement.style.setProperty('--popup-w', `${width}px`);
  document.documentElement.style.setProperty('--popup-h', `${height}px`);
}

export function useResizable() {
  const [size, setSize] = useState(DEFAULT);
  const latest = useRef(DEFAULT);

  // Load persisted size on mount.
  useEffect(() => {
    applyVars(DEFAULT);
    try {
      chrome.storage.local.get([KEY], (res) => {
        const s = res && res[KEY];
        if (s && s.width && s.height) {
          const next = {
            width: clamp(s.width, MIN_W, MAX_W),
            height: clamp(s.height, MIN_H, MAX_H),
          };
          latest.current = next;
          setSize(next);
          applyVars(next);
        }
      });
    } catch (_) {}
  }, []);

  const onResizeStart = useCallback((e) => {
    e.preventDefault();
    const startX = e.clientX;
    const startY = e.clientY;
    const startW = latest.current.width;
    const startH = latest.current.height;

    const onMove = (ev) => {
      const next = {
        width: clamp(startW + (ev.clientX - startX), MIN_W, MAX_W),
        height: clamp(startH + (ev.clientY - startY), MIN_H, MAX_H),
      };
      latest.current = next;
      applyVars(next);
      setSize(next);
    };

    const onUp = () => {
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', onUp);
      try {
        chrome.storage.local.set({ [KEY]: latest.current });
      } catch (_) {}
    };

    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp);
  }, []);

  return { size, onResizeStart };
}

export default useResizable;
