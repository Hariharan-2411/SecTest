class FormScanner {
  constructor() {
    this.scannedElements = [];
    this.scanId = Date.now();
  }

  scanPage() {
    this.scannedElements = [];

    const inputs = document.querySelectorAll('input');
    inputs.forEach((input, index) => {
      const elementInfo = {
        type: 'input',
        subType: input.type || 'text',
        name: input.name || `unnamed_input_${index}`,
        id: input.id || '',
        placeholder: input.placeholder || '',
        value: input.value || '',
        required: input.required,
        xpath: this.getXPath(input),
        element: input,
        uniqueId: `input_${index}_${this.scanId}`
      };
      this.scannedElements.push(elementInfo);
    });

    const textareas = document.querySelectorAll('textarea');
    textareas.forEach((textarea, index) => {
      const elementInfo = {
        type: 'textarea',
        subType: 'textarea',
        name: textarea.name || `unnamed_textarea_${index}`,
        id: textarea.id || '',
        placeholder: textarea.placeholder || '',
        value: textarea.value || '',
        required: textarea.required,
        xpath: this.getXPath(textarea),
        element: textarea,
        uniqueId: `textarea_${index}_${this.scanId}`
      };
      this.scannedElements.push(elementInfo);
    });

    const selects = document.querySelectorAll('select');
    selects.forEach((select, index) => {
      const options = Array.from(select.options).map(opt => opt.value);
      const elementInfo = {
        type: 'select',
        subType: 'select',
        name: select.name || `unnamed_select_${index}`,
        id: select.id || '',
        options: options,
        selectedValue: select.value,
        required: select.required,
        xpath: this.getXPath(select),
        element: select,
        uniqueId: `select_${index}_${this.scanId}`
      };
      this.scannedElements.push(elementInfo);
    });

    const fileInputs = document.querySelectorAll('input[type="file"]');
    fileInputs.forEach((fileInput, index) => {
      const elementInfo = {
        type: 'file',
        subType: 'file',
        name: fileInput.name || `unnamed_file_${index}`,
        id: fileInput.id || '',
        accept: fileInput.accept || '*',
        multiple: fileInput.multiple,
        required: fileInput.required,
        xpath: this.getXPath(fileInput),
        element: fileInput,
        uniqueId: `file_${index}_${this.scanId}`
      };
      this.scannedElements.push(elementInfo);
    });

    return this.scannedElements.map(el => ({...el, element: null}));
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

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'ping') {
    sendResponse({ ok: true });
    return true;
  }

  if (request.action === 'scanPage') {
    const results = scanner.scanPage();
    sendResponse({ success: true, elements: results });
  }

  if (request.action === 'insertTestMarker') {
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
