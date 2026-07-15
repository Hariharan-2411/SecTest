// MAIN-world WebSocket frame shim.
//
// Runs in the PAGE's own realm (manifest `world: "MAIN"`, `run_at
// document_start`) so it can wrap `window.WebSocket` — the isolated content
// script cannot, since it has a separate `window`. It is OBSERVE-ONLY: it
// records the socket URL and a length-capped preview of frames and hands them to
// the isolated content script via `window.postMessage`. It never blocks,
// rewrites, drops, or injects a frame; the native send/receive path is
// untouched. The content script scope-gates before anything is stored.

(function () {
  try {
    const Native = window.WebSocket;
    if (!Native || Native.__irisWrapped) return;

    const CAP = 2000;
    const post = (payload) => {
      try {
        window.postMessage({ __iris_ws: true, ...payload }, '*');
      } catch (_) {}
    };
    const preview = (data) => {
      try {
        if (typeof data === 'string') return data.slice(0, CAP);
        if (typeof Blob !== 'undefined' && data instanceof Blob)
          return `[blob ${data.size}b]`;
        if (data && data.byteLength != null) return `[binary ${data.byteLength}b]`;
      } catch (_) {}
      return '[frame]';
    };

    function Wrapped(url, protocols) {
      const ws = new Native(url, protocols);
      post({ event: 'open', url: String(url) });
      const nativeSend = ws.send.bind(ws);
      ws.send = function (data) {
        post({ event: 'send', url: String(url), data: preview(data) });
        return nativeSend(data);
      };
      try {
        ws.addEventListener('message', (e) => {
          post({ event: 'recv', url: String(url), data: preview(e.data) });
        });
      } catch (_) {}
      return ws; // constructor returns the native instance (overrides `this`)
    }

    Wrapped.prototype = Native.prototype;
    Wrapped.CONNECTING = Native.CONNECTING;
    Wrapped.OPEN = Native.OPEN;
    Wrapped.CLOSING = Native.CLOSING;
    Wrapped.CLOSED = Native.CLOSED;
    Wrapped.__irisWrapped = true;
    window.WebSocket = Wrapped;
  } catch (_) {
    // Never break the page if wrapping fails.
  }
})();
