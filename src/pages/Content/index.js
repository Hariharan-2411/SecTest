console.log('SecTest Pro - Content Script Loaded');

import {
  collectFields,
  extractPageRecon,
  analyzeScriptSource,
} from '../../utils/extraction';
import { isInScope } from '../../utils/scope';
import { summarizeReflection, makeMarker } from '../../utils/reflection';

// Independent scope guard for the content script. DOM-mutating actions (payload
// injection, file attach) are real side effects, so they must be gated on scope
// HERE — not only by the popup UI. We cache the scope from storage and refresh
// it on change so the check at message time is synchronous.
let currentScope = { inScope: ['*'], outOfScope: [] };
try {
  chrome.storage.local.get(['scope'], (r) => {
    if (r && r.scope && Array.isArray(r.scope.inScope)) currentScope = r.scope;
  });
  chrome.storage.onChanged.addListener((changes, ns) => {
    if (ns === 'local' && changes.scope && changes.scope.newValue) {
      currentScope = changes.scope.newValue;
    }
  });
} catch (_) {}

function inScopeHere() {
  return isInScope(window.location.href, currentScope);
}

// Form element scanner. Field extraction now delegates to the tested, pure
// extraction core (src/utils/extraction.js); this class remains the stateful
// adapter that keeps live DOM references for later payload injection.
class FormScanner {
  constructor() {
    this.scannedElements = [];
    this.scanId = Date.now();
    this.lastScanMeta = { unscannable: { crossOriginFrames: 0 } };
  }

  scanPage() {
    this.scanId = Date.now();

    // Deep traversal: light DOM + open shadow roots + same-origin iframes.
    const { fields, unscannable } = collectFields(document.body, {
      scanId: this.scanId,
    });

    // Backfill a name for unnamed fields (preserves the old UI behaviour) and
    // attach an xpath for traceability.
    fields.forEach((f, index) => {
      if (!f.name) f.name = `unnamed_${f.type}_${index}`;
      try {
        if (f.element) f.xpath = this.getXPath(f.element);
      } catch (_) {
        f.xpath = '';
      }
    });

    this.scannedElements = fields;
    this.lastScanMeta = { unscannable };

    console.log(
      `Scanned ${fields.length} form elements ` +
        `(${unscannable.crossOriginFrames} cross-origin frame(s) unscannable)`
    );

    // Strip live DOM references before messaging.
    return fields.map((el) => ({ ...el, element: null }));
  }

  // Read-only passive recon of the current page (no network requests).
  getPageRecon() {
    return extractPageRecon({ documentRef: document, windowRef: window });
  }

  // Full page source / DOM snapshot for offline analysis & reporting.
  getPageSource() {
    return {
      url: window.location.href,
      title: document.title,
      capturedAt: new Date().toISOString(),
      html: document.documentElement.outerHTML,
    };
  }

  getXPath(element) {
    if (element.id !== '') {
      return `//*[@id="${element.id}"]`;
    }
    if (element === document.body) {
      return '/html/body';
    }

    let ix = 0;
    const siblings = element.parentNode?.childNodes || [];
    for (let i = 0; i < siblings.length; i++) {
      const sibling = siblings[i];
      if (sibling === element) {
        return this.getXPath(element.parentNode) + '/' + element.tagName.toLowerCase() + '[' + (ix + 1) + ']';
      }
      if (sibling.nodeType === 1 && sibling.tagName === element.tagName) {
        ix++;
      }
    }
  }

  findElementByUniqueId(uniqueId) {
    const element = this.scannedElements.find(el => el.uniqueId === uniqueId);
    return element ? element.element : null;
  }

  safeSetValue(element, value) {
    if (!element) return { success: false, reason: 'no_element' };
    const tag = element.tagName;
    const type = (element.type || '').toLowerCase();
    if (tag === 'INPUT') {
      const disallowed = new Set([
        'number',
        'range',
        'date',
        'datetime-local',
        'month',
        'week',
        'time',
        'color',
      ]);
      const allowed = new Set(['text', 'search', 'email', 'url', 'tel', 'password']);
      const t = type || 'text';
      if (disallowed.has(t)) {
        return { success: false, reason: 'unsupported_type' };
      }
      if (allowed.has(t)) {
        element.value = value;
        return { success: true };
      }
      try {
        element.value = value;
        return { success: true };
      } catch (e) {
        return { success: false, reason: 'set_failed' };
      }
    }
    if (tag === 'TEXTAREA') {
      element.value = value;
      return { success: true };
    }
    return { success: false, reason: 'unsupported_type' };
  }
}

const scanner = new FormScanner();

// Passive auto-capture: on load, report what the page already exposes so the
// background can accumulate a per-host inventory (scope-gated there). Purely
// read-only — no network requests, no payloads, no DOM changes.
function buildObservation() {
  let recon = {};
  try {
    recon = scanner.getPageRecon() || {};
  } catch (_) {}
  const abs = (v) => {
    try {
      return new URL(v, window.location.href).href;
    } catch (_) {
      return null;
    }
  };
  const links = [];
  try {
    for (const a of document.querySelectorAll('a[href]')) {
      const h = abs(a.getAttribute('href'));
      if (h && /^https?:/i.test(h)) links.push(h);
    }
  } catch (_) {}
  const scripts = [];
  try {
    for (const s of document.querySelectorAll('script[src]')) {
      const h = abs(s.getAttribute('src'));
      if (h) scripts.push(h);
    }
  } catch (_) {}
  return {
    endpoints: recon.endpoints || [],
    links,
    scripts,
    forms: recon.forms || [],
    cookieNames: recon.cookieNames || [],
    secrets: recon.secrets || [],
    sinks: recon.sinks || [],
  };
}

// Deep-JS scan: fetch the page's SAME-ORIGIN external scripts and mine each for
// endpoints, secrets, and DOM-XSS sinks. Same-origin GET only (the browser
// already loaded these), scope-gated, bounded. Folds findings into the per-host
// inventory via the passive-observe path so they accumulate in one place.
const DEEP_JS_MAX = 40;

async function deepJsScan() {
  if (!inScopeHere()) return { success: false, reason: 'out_of_scope' };

  const pageOrigin = window.location.origin;
  const urls = [];
  try {
    for (const s of document.querySelectorAll('script[src]')) {
      let abs = null;
      try {
        abs = new URL(s.getAttribute('src'), window.location.href).href;
      } catch (_) {
        continue;
      }
      // Only same-origin scripts are readable by fetch without CORS.
      if (abs && abs.startsWith(pageOrigin) && !urls.includes(abs)) urls.push(abs);
      if (urls.length >= DEEP_JS_MAX) break;
    }
  } catch (_) {}

  const endpointSet = new Set();
  const secretKeys = new Set();
  const secrets = [];
  const sinks = [];
  const perScript = [];

  for (const url of urls) {
    let text = '';
    let ok = false;
    try {
      const res = await fetch(url, { method: 'GET', credentials: 'omit' });
      ok = res.ok;
      text = await res.text();
    } catch (e) {
      perScript.push({ url, ok: false, error: String(e && e.message) });
      continue;
    }
    const a = analyzeScriptSource(text);
    for (const ep of a.endpoints) endpointSet.add(ep);
    for (const sec of a.secrets) {
      const key = sec.type + ':' + sec.preview;
      if (!secretKeys.has(key)) {
        secretKeys.add(key);
        secrets.push(sec);
      }
    }
    for (const sink of a.sinks) sinks.push(sink);
    perScript.push({
      url,
      ok,
      endpoints: a.endpoints.length,
      secrets: a.secrets.length,
      sinks: a.sinks.length,
    });
  }

  const endpoints = Array.from(endpointSet);

  // Accumulate into the per-host inventory (scope re-checked in the background).
  try {
    chrome.runtime.sendMessage(
      {
        action: 'passiveObserve',
        pageUrl: window.location.href,
        observation: { endpoints, scripts: urls, secrets, sinks },
      },
      () => { void chrome.runtime.lastError; }
    );
  } catch (_) {}

  return {
    success: true,
    scanned: urls.length,
    endpoints,
    secrets,
    sinks,
    perScript,
  };
}

function reportPassiveObservation() {
  try {
    chrome.runtime.sendMessage(
      { action: 'passiveObserve', pageUrl: window.location.href, observation: buildObservation() },
      () => {
        void chrome.runtime.lastError; // no listener / out-of-scope → ignore
      }
    );
  } catch (_) {}
}

if (document.readyState === 'complete') reportPassiveObservation();
else window.addEventListener('load', reportPassiveObservation, { once: true });

// Relay WebSocket frames from the MAIN-world shim (src/pages/WsHook) to the
// background, scope-gated. The shim can wrap window.WebSocket but can't reach
// chrome.*; this isolated content script can. Observe-only.
window.addEventListener('message', (e) => {
  const d = e && e.data;
  if (!d || d.__iris_ws !== true || e.source !== window) return;
  if (!inScopeHere()) return;
  try {
    chrome.runtime.sendMessage(
      {
        action: 'wsFrame',
        pageUrl: window.location.href,
        frame: { event: d.event, url: d.url, data: d.data },
      },
      () => {
        void chrome.runtime.lastError;
      }
    );
  } catch (_) {}
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'ping') {
    sendResponse({ ok: true });
    return true;
  }

  if (request.action === 'scanPage') {
    const results = scanner.scanPage();
    sendResponse({
      success: true,
      elements: results,
      unscannable: scanner.lastScanMeta.unscannable,
    });
  }

  if (request.action === 'getPageRecon') {
    try {
      const recon = scanner.getPageRecon();
      sendResponse({ success: true, recon });
    } catch (e) {
      sendResponse({ success: false, message: String(e && e.message) });
    }
  }

  if (request.action === 'deepJsScan') {
    deepJsScan()
      .then((r) => sendResponse(r))
      .catch((e) => sendResponse({ success: false, reason: String(e && e.message) }));
    return true; // async
  }

  if (request.action === 'extractPageSource') {
    try {
      const source = scanner.getPageSource();
      sendResponse({ success: true, source });
    } catch (e) {
      sendResponse({ success: false, message: String(e && e.message) });
    }
  }

  if (request.action === 'insertTestMarker') {
    if (!inScopeHere()) { sendResponse({ success: false, message: 'out_of_scope' }); return true; }
    const element = scanner.findElementByUniqueId(request.uniqueId);
    if (element) {
      const testMarker = `[TEST_${Date.now()}]`;
      if (element.tagName === 'SELECT') {
        sendResponse({ success: false, message: 'Cannot insert marker in select elements' });
      } else if (element.type === 'file') {
        sendResponse({ success: false, message: 'Cannot insert marker in file inputs' });
      } else {
        element.value = testMarker;
        element.style.border = '2px solid #4CAF50';
        setTimeout(() => {
          element.style.border = '';
        }, 2000);
        sendResponse({
          success: true,
          message: `Inserted: ${testMarker}`,
          details: {
            insertedValue: testMarker,
            inputName: element.name || '',
            elementId: element.id || '',
            elementType: element.tagName.toLowerCase(),
          },
        });
      }
    } else {
      sendResponse({ success: false, message: 'Element not found' });
    }
  }

  if (request.action === 'attachXML') {
    if (!inScopeHere()) { sendResponse({ success: false, message: 'out_of_scope' }); return true; }
    const element = scanner.findElementByUniqueId(request.uniqueId);
    if (element) {
      if (element.type === 'file') {
        const xmlContent = '<?xml version="1.0"?>\n<test>\n  <data>Harmless test payload</data>\n</test>';
        const blob = new Blob([xmlContent], { type: 'text/xml' });
        const file = new File([blob], 'test_payload.xml', { type: 'text/xml' });
        const dataTransfer = new DataTransfer();
        dataTransfer.items.add(file);
        element.files = dataTransfer.files;
        element.style.border = '2px solid #2196F3';
        setTimeout(() => {
          element.style.border = '';
        }, 2000);
        sendResponse({
          success: true,
          message: 'Attached test_payload.xml',
          details: {
            fileName: file.name,
            mimeType: file.type,
            sizeBytes: file.size,
            inputName: element.name || '',
            elementId: element.id || '',
          },
        });
      } else if (element.tagName === 'TEXTAREA' || element.tagName === 'INPUT') {
        const xmlPayload = '<?xml version="1.0"?><test><data>Harmless</data></test>';
        element.value = xmlPayload;
        element.style.border = '2px solid #2196F3';
        setTimeout(() => {
          element.style.border = '';
        }, 2000);
        sendResponse({
          success: true,
          message: 'Inserted XML payload',
          details: {
            insertedValue: xmlPayload,
            inputName: element.name || '',
            elementId: element.id || '',
            elementType: element.tagName.toLowerCase(),
          },
        });
      } else {
        sendResponse({ success: false, message: 'Cannot attach XML to this element type' });
      }
    } else {
      sendResponse({ success: false, message: 'Element not found' });
    }
  }

  if (request.action === 'attachFile') {
    if (!inScopeHere()) { sendResponse({ success: false, reason: 'out_of_scope' }); return true; }
    const { fileData, uniqueIds } = request;
    const idsToUse = Array.isArray(uniqueIds) && uniqueIds.length ? uniqueIds : scanner.scannedElements.map(e => e.uniqueId);
    const results = [];
    for (const id of idsToUse) {
      const element = scanner.findElementByUniqueId(id);
      if (!element) {
        results.push({ uniqueId: id, success: false, reason: 'not_found' });
        continue;
      }
      if (element.type !== 'file') {
        results.push({ uniqueId: id, success: false, reason: 'not_file_input' });
        continue;
      }
      try {
        const b64 = fileData.base64;
        const binaryString = atob(b64);
        const len = binaryString.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
          bytes[i] = binaryString.charCodeAt(i);
        }
        const blob = new Blob([bytes], { type: fileData.mime || 'application/octet-stream' });
        const file = new File([blob], fileData.name || 'upload.bin', { type: fileData.mime || 'application/octet-stream' });
        const dt = new DataTransfer();
        dt.items.add(file);
        element.files = dt.files;
        element.style.border = '2px solid #4CAF50';
        setTimeout(() => { element.style.border = ''; }, 2000);
        results.push({ uniqueId: id, success: true, fileName: file.name, size: file.size });
      } catch (err) {
        results.push({ uniqueId: id, success: false, reason: 'attach_failed' });
      }
    }
    sendResponse({ success: true, results });
    return true;
  }

  if (request.action === 'confirmReflection') {
    if (!inScopeHere()) { sendResponse({ success: false, reason: 'out_of_scope' }); return true; }
    const idsToUse = Array.isArray(request.uniqueIds) && request.uniqueIds.length
      ? request.uniqueIds
      : scanner.scannedElements.map((e) => e.uniqueId);
    const results = [];
    for (const id of idsToUse) {
      const el = scanner.findElementByUniqueId(id);
      if (!el) { results.push({ uniqueId: id, success: false, reason: 'not_found' }); continue; }
      if (el.tagName === 'SELECT' || (el.type && el.type.toLowerCase() === 'file')) {
        results.push({ uniqueId: id, success: false, reason: 'unsupported_field' });
        continue;
      }
      // Inject a unique benign marker, fire input/change so any client-side
      // handler that echoes the field runs, then read the DOM back. DOM-only —
      // no network, no exploit — and the original value is restored afterwards.
      const original = el.value;
      const marker = makeMarker();
      const set = scanner.safeSetValue(el, marker);
      if (!set.success) { results.push({ uniqueId: id, success: false, reason: set.reason }); continue; }
      try {
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
      } catch (_) {}
      let urlReflected = false;
      try { urlReflected = window.location.href.includes(marker); } catch (_) {}
      let html = '';
      try { html = document.documentElement.outerHTML; } catch (_) {}
      const summary = summarizeReflection(html, marker, { urlReflected });
      // Restore the field to its original value.
      try {
        el.value = original;
        el.dispatchEvent(new Event('input', { bubbles: true }));
      } catch (_) {}
      if (summary.reflected) {
        el.style.border = '2px solid #ff5c7c';
        setTimeout(() => (el.style.border = ''), 1500);
      }
      results.push({
        uniqueId: id,
        success: true,
        reflected: summary.reflected,
        contexts: summary.contexts,
        count: summary.count,
      });
    }
    sendResponse({ success: true, results });
    return true;
  }

  if (request.action === 'executeVulnTest') {
    if (!inScopeHere()) { sendResponse({ success: false, reason: 'out_of_scope' }); return true; }
    const { vulnKey, payloads, uniqueIds } = request;
    const results = [];
    const idsToUse = Array.isArray(uniqueIds) && uniqueIds.length ? uniqueIds : scanner.scannedElements.map(e => e.uniqueId);
    idsToUse.forEach((id) => {
      const el = scanner.findElementByUniqueId(id);
      if (!el) {
        results.push({ uniqueId: id, success: false, reason: 'not_found' });
        return;
      }
      if (el.tagName === 'SELECT' || (el.type && el.type.toLowerCase() === 'file')) {
        results.push({ uniqueId: id, success: false, reason: 'unsupported_field' });
        return;
      }
      let applied = false;
      for (const p of payloads || []) {
        const r = scanner.safeSetValue(el, p);
        if (r.success) {
          el.style.border = '2px dashed #ff9800';
          setTimeout(() => (el.style.border = ''), 1500);
          results.push({ uniqueId: id, success: true, payload: p });
          applied = true;
          break;
        }
      }
      if (!applied) {
        results.push({ uniqueId: id, success: false, reason: 'no_payload_applied' });
      }
    });
    sendResponse({ success: true, vulnKey, results });
  }

  return true;
});
