import React, {
  createContext,
  useContext,
  useState,
  useCallback,
  useMemo,
  useRef,
} from 'react';

// Lightweight toast system. Replaces alert() across the popup: anything under
// <ToastProvider> can call useToast() and push a dismissible, auto-expiring
// message without knowing how the stack is rendered.

const ToastContext = createContext(null);

let idSeq = 0;

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  const timers = useRef({});

  const dismiss = useCallback((id) => {
    setToasts((list) => list.filter((t) => t.id !== id));
    if (timers.current[id]) {
      clearTimeout(timers.current[id]);
      delete timers.current[id];
    }
  }, []);

  const push = useCallback(
    (message, type = 'info', ttl = 4000) => {
      const id = ++idSeq;
      setToasts((list) => [...list, { id, message: String(message), type }]);
      if (ttl > 0) {
        timers.current[id] = setTimeout(() => dismiss(id), ttl);
      }
      return id;
    },
    [dismiss]
  );

  const api = useMemo(
    () => ({
      show: (m, type = 'info', ttl) => push(m, type, ttl),
      info: (m, ttl) => push(m, 'info', ttl),
      success: (m, ttl) => push(m, 'success', ttl),
      error: (m, ttl) => push(m, 'error', ttl),
      dismiss,
    }),
    [push, dismiss]
  );

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div className="toast-stack" role="status" aria-live="polite">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={`toast toast-${t.type}`}
            onClick={() => dismiss(t.id)}
            title="Dismiss"
          >
            {t.message}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) {
    throw new Error('useToast must be used within a <ToastProvider>');
  }
  return ctx;
}

export default ToastProvider;
