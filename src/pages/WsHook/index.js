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

// MAIN-world console/error/CSP observers — an OBSERVE-ONLY recon signal. Wraps
// console.error/warn (still calling the native method) and listens for uncaught
// errors, promise rejections, and CSP violations, posting compact, length-capped
// previews to the isolated content script in small batches. It never suppresses
// or alters the page's own logging/error behavior.
(function () {
  try {
    if (window.__irisConsoleWrapped) return;
    window.__irisConsoleWrapped = true;

    const CAP = 1000;
    const MAX_BATCH = 20;
    let batch = [];
    let timer = null;

    const flush = () => {
      timer = null;
      if (!batch.length) return;
      const events = batch.slice(0, MAX_BATCH);
      batch = [];
      try {
        window.postMessage({ __iris_console: true, events }, '*');
      } catch (_) {}
    };
    const push = (ev) => {
      if (batch.length < 200) batch.push(ev);
      if (!timer) timer = setTimeout(flush, 800);
    };
    const clip = (v) => {
      try {
        return (typeof v === 'string' ? v : String(v)).slice(0, CAP);
      } catch (_) {
        return '';
      }
    };
    const joinArgs = (args) => {
      try {
        return Array.prototype.map.call(args, clip).join(' ').slice(0, CAP);
      } catch (_) {
        return '';
      }
    };

    ['error', 'warn'].forEach((level) => {
      const native = console[level] ? console[level].bind(console) : null;
      if (!native) return;
      console[level] = function () {
        try {
          push({ kind: level, message: joinArgs(arguments) });
        } catch (_) {}
        return native.apply(console, arguments);
      };
    });

    window.addEventListener('error', (e) => {
      try {
        push({
          kind: 'onerror',
          message: clip(e && e.message),
          stack: clip(e && e.error && e.error.stack),
          source: clip(e && e.filename),
        });
      } catch (_) {}
    });
    window.addEventListener('unhandledrejection', (e) => {
      try {
        const r = e && e.reason;
        push({
          kind: 'unhandledrejection',
          message: clip(r && r.message ? r.message : r),
          stack: clip(r && r.stack),
        });
      } catch (_) {}
    });
    document.addEventListener('securitypolicyviolation', (e) => {
      try {
        push({
          kind: 'csp',
          violatedDirective: clip(e && e.violatedDirective),
          blockedURI: clip(e && e.blockedURI),
        });
      } catch (_) {}
    });
  } catch (_) {
    // Never break the page if observing fails.
  }
})();

// MAIN-world DOM-XSS canary probe runner (B2). OBSERVE-ONLY reachability check:
// interprets a whitelisted DATA descriptor from the isolated content script — sets
// a benign canary at a whitelisted source, observes whether it reaches the DOM,
// then restores the source. It NEVER evaluates descriptor content and never injects
// exploit code; it only checks whether controllable input can reach a sink.
(function () {
  try {
    if (window.__irisProbeWrapped) return;
    window.__irisProbeWrapped = true;

    const setSource = (source, canary) => {
      if (source === 'location.hash') {
        const prev = location.hash;
        try { location.hash = '#' + canary; } catch (_) {}
        return () => { try { location.hash = prev; } catch (_) {} };
      }
      if (source === 'window.name') {
        const prev = window.name;
        try { window.name = canary; } catch (_) {}
        return () => { try { window.name = prev; } catch (_) {} };
      }
      return () => {};
    };

    window.addEventListener('message', (e) => {
      const d = e && e.data;
      if (!d || d.__iris_probe_run !== true || e.source !== window) return;
      const desc = d.descriptor || {};
      const canary = String(desc.canary || '');
      const reply = (result) => {
        try {
          window.postMessage({ __iris_probe_result: true, id: d.id, findingId: desc.findingId, canary, result }, '*');
        } catch (_) {}
      };
      // Only run whitelisted, well-formed canary probes.
      if (!/^IRIS_CANARY_[A-Za-z0-9_]+$/.test(canary) || (desc.source !== 'location.hash' && desc.source !== 'window.name')) {
        reply({ reachedSink: false, error: 'rejected' });
        return;
      }
      const restore = setSource(desc.source, canary);
      setTimeout(() => {
        let reached = false;
        try {
          const html = document.documentElement ? document.documentElement.innerHTML : '';
          reached = html.indexOf(canary) !== -1;
        } catch (_) {}
        restore();
        // The canary is [A-Za-z0-9_] only — if it appears raw in the HTML it was
        // NOT entity-encoded, i.e. it reached a sink unescaped.
        reply({ reachedSink: reached, unescaped: reached, sinkType: desc.sink, source: desc.source });
      }, 120);
    });
  } catch (_) {
    // Never break the page if the probe runner fails.
  }
})();
