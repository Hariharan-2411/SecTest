console.log('SecTest Pro - Content Script Loaded');

import {
  collectFields,
  extractPageRecon,
} from '../../utils/extraction';

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

  // Safely set a value on a compatible element
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
      // default: attempt to set on other textual types
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

// Message listener for popup communication
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log('Content script received message:', request);

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

  if (request.action === 'extractPageSource') {
    try {
      const source = scanner.getPageSource();
      sendResponse({ success: true, source });
    } catch (e) {
      sendResponse({ success: false, message: String(e && e.message) });
    }
  }

  if (request.action === 'insertTestMarker') {
    const element = scanner.findElementByUniqueId(request.uniqueId);
    if (element) {
      const testMarker = `[TEST_${Date.now()}]`;
      if (element.tagName === 'SELECT') {
        // For select, we can't insert text, just log
        console.log(`Cannot insert test marker in SELECT element: ${element.name}`);
        sendResponse({ success: false, message: 'Cannot insert marker in select elements' });
      } else if (element.type === 'file') {
        console.log(`Cannot insert test marker in FILE input: ${element.name}`);
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
    const element = scanner.findElementByUniqueId(request.uniqueId);
    if (element) {
      if (element.type === 'file') {
        // Create a harmless XML file blob
        const xmlContent = '<?xml version="1.0"?>\n<test>\n  <data>Harmless test payload</data>\n</test>';
        const blob = new Blob([xmlContent], { type: 'text/xml' });
        const file = new File([blob], 'test_payload.xml', { type: 'text/xml' });
        
        // Create a new FileList-like object
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
    const { fileData, uniqueIds } = request;
    // fileData: { base64, mime, name }
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
        // Decode base64 to Uint8Array
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
        console.error('attachFile error', err);
        results.push({ uniqueId: id, success: false, reason: 'attach_failed' });
      }
    }
    sendResponse({ success: true, results });
    return true;
  }

  // Execute a vulnerability test by injecting payloads into compatible fields
  if (request.action === 'executeVulnTest') {
    const { vulnKey, payloads, uniqueIds } = request;
    const results = [];
    const idsToUse = Array.isArray(uniqueIds) && uniqueIds.length ? uniqueIds : scanner.scannedElements.map(e => e.uniqueId);
    idsToUse.forEach((id) => {
      const el = scanner.findElementByUniqueId(id);
      if (!el) {
        results.push({ uniqueId: id, success: false, reason: 'not_found' });
        return;
      }
      // Skip selects and file inputs for text payloads
      if (el.tagName === 'SELECT' || (el.type && el.type.toLowerCase() === 'file')) {
        results.push({ uniqueId: id, success: false, reason: 'unsupported_field' });
        return;
      }
      // Try each payload; record the first success
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

  return true; // Keep channel open for async response
});
