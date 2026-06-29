import React, { useState, useEffect } from 'react';
import './Popup.css';
import { DEFAULT_VULNS } from '../../utils/payloads';
import OllamaPayloadAssistant from '../../utils/ollamaIntegration';

const Popup = () => {
  const [elements, setElements] = useState([]);
  const [selectedIds, setSelectedIds] = useState(new Set());
  const [loading, setLoading] = useState(false);
  const [currentUrl, setCurrentUrl] = useState('');
  const [allowlist, setAllowlist] = useState([]);
  const [dryRunMode, setDryRunMode] = useState(true);
  const [auditLog, setAuditLog] = useState([]);
  const [showSettings, setShowSettings] = useState(false);
  const [newHost, setNewHost] = useState('');
  const [confirmAction, setConfirmAction] = useState(null);
  const [selectedVuln, setSelectedVuln] = useState(DEFAULT_VULNS[0].key);
  const [payloadSource, setPayloadSource] = useState('library'); // 'file' | 'text' | 'llm' | 'library'
  const [filePayload, setFilePayload] = useState('');
  const [fileName, setFileName] = useState('');
  const [textPayload, setTextPayload] = useState('');
  const [fileData, setFileData] = useState(null); // { base64, mime, name }
  const [llmPayload, setLlmPayload] = useState('');
  const [llmLoading, setLlmLoading] = useState(false);
  const [ollamaAvailable, setOllamaAvailable] = useState(false);
  const [ollama] = useState(() => {
    try {
      return new OllamaPayloadAssistant();
    } catch (e) {
      return null;
    }
  });
  const [ollamaUrl, setOllamaUrl] = useState('http://127.0.0.1:11434');
  const [ollamaModel, setOllamaModel] = useState('llama3.2:1b');
  const [ollamaError, setOllamaError] = useState('');
  const [ollamaStatus, setOllamaStatus] = useState('');
  const [activeTab, setActiveTab] = useState('Scan'); // 'Scan' | 'Payloads' | 'Recon' | 'History' | 'Settings'
  const [payloadHistory, setPayloadHistory] = useState([]);
  const [recon, setRecon] = useState(null); // passive page recon snapshot
  const [reconLoading, setReconLoading] = useState(false);
  const [activeReconResult, setActiveReconResult] = useState(null); // result of active recon
  const [unscannable, setUnscannable] = useState(null); // { crossOriginFrames }
  // Capture extension id for origin guidance
  const extensionId = chrome?.runtime?.id || '<extension-id>'; // used in 403 guidance/help text

  useEffect(() => {
    // Load settings from storage
    chrome.storage.local.get(['allowlist', 'dryRunMode', 'auditLog'], (result) => {
      setAllowlist(result.allowlist || ['*']);
      setDryRunMode(result.dryRunMode !== undefined ? result.dryRunMode : true);
      setAuditLog(result.auditLog || []);
      setPayloadHistory(result.payloadHistory || []);
    });

    // Get current tab URL
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        setCurrentUrl(tabs[0].url);
      }
    });

    // Check Ollama availability in the background
    (async () => {
      try {
        if (ollama) {
          ollama.setBaseUrl(ollamaUrl);
          ollama.setModel(ollamaModel);
        }
        if (ollama && (await ollama.checkAvailability())) {
          setOllamaAvailable(true);
          setOllamaError('');
        } else {
          setOllamaAvailable(false);
          setOllamaError(ollama?.getLastError?.() || '');
        }
      } catch (_) {
        setOllamaAvailable(false);
        setOllamaError(ollama?.getLastError?.() || '');
      }
    })();
  }, []);

  const isHostAllowed = (url) => {
    try {
      const hostname = new URL(url).hostname;
      if (allowlist.includes('*')) return true;
      return allowlist.some(allowed => hostname.includes(allowed));
    } catch (e) {
      return false;
    }
  };

  const addToAuditLog = (action, elementInfo, result) => {
    const logEntry = {
      timestamp: new Date().toISOString(),
      action,
      url: currentUrl,
      element: elementInfo,
      result,
      dryRun: dryRunMode
    };

    const newLog = [logEntry, ...auditLog].slice(0, 100); // Keep last 100 entries
    setAuditLog(newLog);
    chrome.storage.local.set({ auditLog: newLog });
  };

  const toggleSelection = (uniqueId) => {
    setSelectedIds(prev => {
      const copy = new Set(prev);
      if (copy.has(uniqueId)) copy.delete(uniqueId);
      else copy.add(uniqueId);
      return copy;
    });
  };

  const selectAll = () => {
    setSelectedIds(new Set(elements.map(e => e.uniqueId)));
  };

  const clearSelection = () => {
    setSelectedIds(new Set());
  };

  const selectFilesOnly = () => {
    setSelectedIds(new Set(elements.filter(e => e.type === 'file').map(e => e.uniqueId)));
  };

  // Best-effort ping. Reading chrome.runtime.lastError inside the callback
  // suppresses the "Unchecked runtime.lastError: Could not establish
  // connection" console noise that fires when no content script is listening.
  const pingTab = (tabId) =>
    new Promise((resolve) => {
      let settled = false;
      const done = (ok) => {
        if (!settled) {
          settled = true;
          resolve(ok);
        }
      };
      try {
        chrome.tabs.sendMessage(tabId, { action: 'ping' }, (resp) => {
          void chrome.runtime.lastError; // read to acknowledge / clear the error
          done(Boolean(resp && resp.ok));
        });
      } catch (_) {
        done(false);
      }
      setTimeout(() => done(false), 500);
    });

  // Ensure the content script is live in the target tab. Content scripts are
  // only auto-injected on page load, so a tab that was already open when the
  // extension was (re)loaded won't have one — that's the "Receiving end does
  // not exist" error. If the ping fails, inject the script on demand via
  // chrome.scripting, then re-ping to confirm. Returns true when reachable.
  const ensureContentScript = async (tab) => {
    if (!tab || tab.id == null) return false;
    if (await pingTab(tab.id)) return true;

    // chrome.scripting can't touch restricted pages (chrome://, view-source,
    // the Web Store, etc.) — only http/https are injectable here.
    if (!/^https?:\/\//i.test(tab.url || '')) return false;

    try {
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        files: ['contentScript.bundle.js'],
      });
    } catch (e) {
      console.error('Content script injection failed:', e);
      return false;
    }
    return pingTab(tab.id);
  };

  const scanPage = async () => {
    if (!isHostAllowed(currentUrl)) {
      alert('⚠️ Current host is not in allowlist! Add it in settings first.');
      return;
    }

    setLoading(true);
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      // Ensure the content script is present (inject it if the page predates the
      // extension load) before messaging.
      const ready = await ensureContentScript(tab);
      if (!ready) {
        alert('Content script could not be reached on this page. Open a normal http(s) page and try again.');
        setLoading(false);
        return;
      }

      chrome.tabs.sendMessage(tab.id, { action: 'scanPage' }, (response) => {
        if (chrome.runtime.lastError) {
          console.error('Error:', chrome.runtime.lastError);
          alert('Error: Please refresh the page and try again.');
          setLoading(false);
          return;
        }

        if (response && response.success) {
          setElements(response.elements);
          setUnscannable(response.unscannable || null);
          addToAuditLog('SCAN', { count: response.elements.length }, 'SUCCESS');
        }
        setLoading(false);
      });
    } catch (error) {
      console.error('Scan error:', error);
      setLoading(false);
    }
  };

  // Passive recon: ask the content script to read the loaded page (no requests).
  const runRecon = async () => {
    if (!isHostAllowed(currentUrl)) {
      alert('⚠️ Current host is not in allowlist! Add it in settings first.');
      return;
    }
    setReconLoading(true);
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      const ready = await ensureContentScript(tab);
      if (!ready) {
        alert('Content script could not be reached on this page. Open a normal http(s) page and try again.');
        setReconLoading(false);
        return;
      }
      chrome.tabs.sendMessage(tab.id, { action: 'getPageRecon' }, (response) => {
        const lastErr = chrome.runtime.lastError && chrome.runtime.lastError.message;
        if (response && response.success) {
          setRecon(response.recon);
          addToAuditLog('PASSIVE_RECON', { endpoints: response.recon.endpoints?.length || 0 }, 'SUCCESS');
        } else {
          alert('❌ Recon failed: ' + (response?.message || lastErr || 'unknown error'));
        }
        setReconLoading(false);
      });
    } catch (e) {
      console.error('Recon error', e);
      setReconLoading(false);
    }
  };

  // Light active recon (background worker). Honors allowlist + dry-run + rate-limit.
  const runActiveRecon = (includeDiscovered = false) => {
    const endpoints = (recon && recon.endpoints) || [];
    chrome.runtime.sendMessage(
      { action: 'activeRecon', pageUrl: currentUrl, endpoints, includeDiscovered },
      (response) => {
        if (chrome.runtime.lastError) {
          alert('Error: ' + chrome.runtime.lastError.message);
          return;
        }
        setActiveReconResult(response);
        if (response && response.success && response.dryRun) {
          alert(`🔒 DRY RUN: would fetch ${response.wouldFetch.length} URL(s). Disable Dry Run to execute.`);
        } else if (response && !response.success) {
          alert('❌ Active recon blocked: ' + (response.reason || 'unknown'));
        }
      }
    );
  };

  const probeEndpoint = (endpoint) => {
    chrome.runtime.sendMessage(
      { action: 'probeEndpoint', pageUrl: currentUrl, endpoint },
      (response) => {
        if (chrome.runtime.lastError) {
          alert('Error: ' + chrome.runtime.lastError.message);
          return;
        }
        if (response && response.success && response.dryRun) {
          alert(`🔒 DRY RUN: would GET ${response.wouldFetch}`);
        } else if (response && response.success) {
          const r = response.result || {};
          alert(`Probed ${r.url}\nStatus: ${r.status} ${r.ok ? '✅' : ''}`);
        } else {
          alert('❌ Probe blocked: ' + (response?.reason || 'unknown'));
        }
      }
    );
  };

  // Export full page source / DOM snapshot for offline analysis.
  const exportPageSource = async () => {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      const ready = await ensureContentScript(tab);
      if (!ready) {
        alert('Content script could not be reached on this page. Open a normal http(s) page and try again.');
        return;
      }
      chrome.tabs.sendMessage(tab.id, { action: 'extractPageSource' }, (response) => {
        if (response && response.success) {
          const blob = new Blob([JSON.stringify(response.source, null, 2)], { type: 'application/json' });
          const url = URL.createObjectURL(blob);
          const link = document.createElement('a');
          link.href = url;
          link.download = `page_source_${Date.now()}.json`;
          link.click();
          addToAuditLog('EXPORT_PAGE_SOURCE', { url: response.source.url }, 'SUCCESS');
        } else {
          alert('❌ Could not capture page source');
        }
      });
    } catch (e) {
      alert('Export failed: ' + e.message);
    }
  };

  const confirmAndExecute = (action, element, callback) => {
    if (dryRunMode) {
      alert(`🔒 DRY RUN MODE: Would execute ${action} on ${element.name || element.type}`);
      addToAuditLog(action, element, 'DRY_RUN');
      return;
    }

    setConfirmAction({
      message: `Execute ${action} on "${element.name || element.type}"?`,
      onConfirm: callback
    });
  };

  const handleConfirm = () => {
    if (confirmAction && confirmAction.onConfirm) {
      confirmAction.onConfirm();
    }
    setConfirmAction(null);
  };

  const handleCancel = () => {
    setConfirmAction(null);
  };

  // per-field actions removed from UI per request

  const readFileAsText = (file) => new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = reject;
    reader.readAsText(file);
  });

  const readFileAsBase64 = (file) => new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const arrayBuffer = reader.result;
        const bytes = new Uint8Array(arrayBuffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
        const b64 = btoa(binary);
        resolve({ base64: b64, mime: file.type || 'application/octet-stream', name: file.name || 'upload.bin', arrayBuffer });
      } catch (e) {
        reject(e);
      }
    };
    reader.onerror = reject;
    reader.readAsArrayBuffer(file);
  });

  const onFileChange = async (e) => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    try {
      setFileName(file.name || '');
      // read binary/base64 for file attachment
      const b = await readFileAsBase64(file);
      setFileData({ base64: b.base64, mime: b.mime, name: b.name });
      // also attempt to decode text payload for convenience
      try {
        const text = new TextDecoder('utf-8').decode(new Uint8Array(b.arrayBuffer));
        setFilePayload(String(text));
      } catch (_) {
        setFilePayload('');
      }
      setPayloadSource('file');
    } catch (err) {
      alert('Failed to read file');
    }
  };

  const fetchLlmSuggestion = async () => {
    if (!ollama) return;
    const vuln = DEFAULT_VULNS.find(v => v.key === selectedVuln);
    setLlmLoading(true);
    try {
      const suggestion = await ollama.generatePayload({
        elementType: 'input',
        elementName: '*',
        testType: 'Payload Generation',
        vulnerability: vuln?.label || selectedVuln,
      });
      setLlmPayload(suggestion.payload || '');
      setPayloadSource('llm');
    } catch (e) {
      const msg = ollama?.getLastError?.() || e?.message || 'LLM not available or failed to generate.';
      alert(msg);
      setOllamaError(msg);
    } finally {
      setLlmLoading(false);
    }
  };

  const runVulnTest = async () => {
    const vuln = DEFAULT_VULNS.find(v => v.key === selectedVuln);
    if (!vuln) return;
    // Determine payloads based on selected source
    let payloads = vuln.payloads;
    if (payloadSource === 'file' && filePayload.trim()) {
      payloads = filePayload.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    } else if (payloadSource === 'text' && textPayload.trim()) {
      payloads = textPayload.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    } else if (payloadSource === 'llm' && llmPayload.trim()) {
      payloads = [llmPayload.trim()];
    }
    const executeAction = async () => {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      const ready = await ensureContentScript(tab);
      if (!ready) {
        alert('Content script could not be reached on this page. Open a normal http(s) page and try again.');
        return;
      }
      // send only selected uniqueIds (if any); otherwise target all elements
      const targetIds = (selectedIds && selectedIds.size > 0)
        ? Array.from(selectedIds)
        : elements.map(e => e.uniqueId);
      if (payloadSource === 'file' && fileData) {
        // Attach file(s) to file inputs on page
        chrome.tabs.sendMessage(
          tab.id,
          {
            action: 'attachFile',
            fileData,
            uniqueIds: targetIds,
          },
          (response) => {
            if (response && response.success) {
              const successCount = response.results.filter(r => r.success).length;
              alert(`✅ File attached to ${successCount}/${response.results.length} fields`);
              addToAuditLog('ATTACH_FILE', { file: fileData.name, results: response.results }, 'SUCCESS');
              try {
                savePayloadHistory({
                  timestamp: new Date().toISOString(),
                  vuln: vuln.key,
                  payloadSource,
                  payloads: [fileData.name],
                  targets: targetIds,
                });
              } catch (e) { console.warn('Could not save payload history', e); }
            } else {
              alert('❌ Failed to attach file');
              addToAuditLog('ATTACH_FILE', { file: fileData.name }, 'FAILED');
            }
          }
        );
      } else {
        chrome.tabs.sendMessage(
          tab.id,
          {
            action: 'executeVulnTest',
            vulnKey: vuln.key,
            payloads,
            uniqueIds: targetIds,
          },
          (response) => {
            if (response && response.success) {
              const successCount = response.results.filter(r => r.success).length;
              alert(`✅ ${vuln.label} test applied to ${successCount}/${response.results.length} fields`);
              addToAuditLog('VULN_TEST', { vuln: vuln.key, results: response.results }, 'SUCCESS');
              // Save to payload history for later reuse
              try {
                savePayloadHistory({
                  timestamp: new Date().toISOString(),
                  vuln: vuln.key,
                  payloadSource,
                  payloads,
                  targets: targetIds,
                });
              } catch (e) {
                console.warn('Could not save payload history', e);
              }
            } else {
              alert('❌ Failed to execute test');
              addToAuditLog('VULN_TEST', { vuln: vuln.key }, 'FAILED');
            }
          }
        );
      }
    };

    confirmAndExecute(`${vuln.label} Test`, { name: vuln.key, type: 'vuln' }, executeAction);
  };

  const addToAllowlist = () => {
    if (newHost && !allowlist.includes(newHost)) {
      const updated = [...allowlist, newHost];
      setAllowlist(updated);
      chrome.storage.local.set({ allowlist: updated });
      setNewHost('');
    }
  };

  const removeFromAllowlist = (host) => {
    const updated = allowlist.filter(h => h !== host);
    setAllowlist(updated);
    chrome.storage.local.set({ allowlist: updated });
  };

  const toggleDryRun = () => {
    const newMode = !dryRunMode;
    setDryRunMode(newMode);
    chrome.storage.local.set({ dryRunMode: newMode });
  };

  const exportAuditLog = () => {
    const dataStr = JSON.stringify(auditLog, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `audit_log_${Date.now()}.json`;
    link.click();
  };

  const getElementIcon = (type) => {
    const icons = {
      input: (
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <rect x="3" y="8" width="18" height="8" rx="2"/><path d="M7 12h0"/>
        </svg>
      ),
      textarea: (
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <rect x="3" y="3" width="18" height="18" rx="2"/><line x1="7" y1="8" x2="17" y2="8"/><line x1="7" y1="12" x2="17" y2="12"/><line x1="7" y1="16" x2="13" y2="16"/>
        </svg>
      ),
      select: (
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <rect x="3" y="8" width="18" height="8" rx="2"/><path d="m15 11 2 2 2-2"/>
        </svg>
      ),
      file: (
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="12" y1="18" x2="12" y2="12"/><line x1="9" y1="15" x2="15" y2="15"/>
        </svg>
      ),
    };
    return icons[type] || (
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="3"/>
      </svg>
    );
  };

  // Persist a payload history entry (most recent first, capped)
  const savePayloadHistory = (entry) => {
    setPayloadHistory(prev => {
      const next = [entry, ...prev].slice(0, 50);
      try { chrome.storage.local.set({ payloadHistory: next }); } catch (e) { /* ignore */ }
      return next;
    });
  };

  const insertHistoryEntry = (entry) => {
    if (!entry || !entry.payloads) return;
    // populate the Payloads tab with the saved payloads (text mode)
    setPayloadSource('text');
    setTextPayload(entry.payloads.join('\n'));
    setActiveTab('Payloads');
  };

  const copyHistoryEntry = async (entry) => {
    if (!entry || !entry.payloads) return;
    const text = entry.payloads.join('\n');
    try { await navigator.clipboard.writeText(text); } catch (e) { alert('Copy failed'); }
  };

  const deleteHistoryEntry = (index) => {
    setPayloadHistory(prev => {
      const copy = [...prev];
      copy.splice(index, 1);
      try { chrome.storage.local.set({ payloadHistory: copy }); } catch (e) { /* ignore */ }
      return copy;
    });
  };

  const IconShield = () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  );
  const IconScan = () => (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
    </svg>
  );
  const IconPayloads = () => (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>
    </svg>
  );
  const IconRecon = () => (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M4.9 19.1C1 15.2 1 8.8 4.9 4.9"/><path d="M7.8 16.2c-2.3-2.3-2.3-6.1 0-8.5"/>
      <circle cx="12" cy="12" r="2"/>
      <path d="M16.2 7.8c2.3 2.3 2.3 6.1 0 8.5"/><path d="M19.1 4.9C23 8.8 23 15.2 19.1 19.1"/>
    </svg>
  );
  const IconHistory = () => (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
    </svg>
  );
  const IconConfig = () => (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="4" y1="6" x2="20" y2="6"/><line x1="4" y1="12" x2="20" y2="12"/><line x1="4" y1="18" x2="20" y2="18"/>
      <circle cx="8" cy="6" r="2" fill="currentColor" stroke="none"/><circle cx="16" cy="12" r="2" fill="currentColor" stroke="none"/><circle cx="10" cy="18" r="2" fill="currentColor" stroke="none"/>
    </svg>
  );

  return (
    <div className="sectest-container">
      <div className="header">
        <h2>
          <span className="header-icon"><IconShield /></span>
          SecTest Pro
        </h2>
        <div className={`status-badge${dryRunMode ? '' : ' live'}`}>
          {dryRunMode ? 'Dry Run' : 'Live'}
        </div>
      </div>

      {!isHostAllowed(currentUrl) && (
        <div className="warning-banner">
          Host not in allowlist — add it in Config
        </div>
      )}

      <div className="tab-nav">
        <button className={"tab" + (activeTab === 'Scan' ? ' active' : '')} onClick={() => setActiveTab('Scan')} aria-label="Scan">
          <IconScan />Scan
        </button>
        <button className={"tab" + (activeTab === 'Payloads' ? ' active' : '')} onClick={() => setActiveTab('Payloads')} aria-label="Payloads">
          <IconPayloads />Payloads
        </button>
        <button className={"tab" + (activeTab === 'Recon' ? ' active' : '')} onClick={() => setActiveTab('Recon')} aria-label="Recon">
          <IconRecon />Recon
        </button>
        <button className={"tab" + (activeTab === 'History' ? ' active' : '')} onClick={() => setActiveTab('History')} aria-label="History">
          <IconHistory />History
        </button>
        <button className={"tab" + (activeTab === 'Settings' ? ' active' : '')} onClick={() => setActiveTab('Settings')} aria-label="Config">
          <IconConfig />Config
        </button>
      </div>

      {activeTab === 'Scan' && (
        <div>
          <div className="controls">
            <button onClick={scanPage} disabled={loading} className="btn-primary">
              {loading ? 'Scanning...' : 'Scan Page'}
            </button>
            <button onClick={() => setActiveTab('Settings')} className="btn-secondary">
              Config
            </button>
            <div className="vuln-runner">
              <select value={selectedVuln} onChange={(e) => setSelectedVuln(e.target.value)}>
                {DEFAULT_VULNS.map((v) => (
                  <option key={v.key} value={v.key}>{v.label}</option>
                ))}
              </select>
              <button onClick={runVulnTest} className="btn-secondary" disabled={!isHostAllowed(currentUrl)}>
                Run Test
              </button>
            </div>
          </div>

          <div className="elements-list">
            {elements.length > 0 && (
              <div className="stats">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>Found {elements.length} form elements</div>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button className="btn-small" onClick={selectAll}>Select all</button>
                    <button className="btn-small" onClick={clearSelection}>Clear</button>
                    <button className="btn-small" onClick={selectFilesOnly}>Select files</button>
                  </div>
                </div>
              </div>
            )}

            {elements.map((element, idx) => (
              <div key={idx} className="element-card">
                <div className="element-header">
                  <input
                    type="checkbox"
                    style={{ marginRight: 8 }}
                    checked={selectedIds && selectedIds.has && selectedIds.has(element.uniqueId)}
                    onChange={() => toggleSelection(element.uniqueId)}
                    title="Select this field for payloads/attachments"
                  />
                  <span className="element-icon">{getElementIcon(element.type)}</span>
                  <span className="element-type">{element.type}</span>
                  <span className="element-name">{element.name || 'unnamed'}</span>
                </div>

                {element.tags && element.tags.length > 0 && (
                  <div className="tag-row">
                    {element.tags.map((t) => (
                      <span key={t} className={'tag tag-' + t}>{t}</span>
                    ))}
                  </div>
                )}

                <div className="element-details">
                  {element.subType && <div>Type: {element.subType}</div>}
                  {element.id && <div>ID: {element.id}</div>}
                  {element.context && element.context !== 'light' && <div>Context: {element.context}</div>}
                  {element.formMethod && <div>Form: {element.formMethod.toUpperCase()} {element.formAction || '(self)'}</div>}
                  {element.placeholder && <div>Placeholder: {element.placeholder}</div>}
                  {element.maxlength != null && <div>Maxlength: {element.maxlength}</div>}
                  {element.pattern && <div>Pattern: <code>{element.pattern}</code></div>}
                  {element.required && <div className="badge-required">Required</div>}
                </div>
              </div>
            ))}
          </div>
          {unscannable && unscannable.crossOriginFrames > 0 && (
            <div className="hint">
              ⚠️ {unscannable.crossOriginFrames} cross-origin frame(s) could not be scanned.
            </div>
          )}
        </div>
      )}

      {activeTab === 'Payloads' && (
        <div className="payload-sources">
          <h3>Payload Source</h3>
          <div className="source-options">
            <label>
              <input
                type="radio"
                name="payloadSource"
                value="library"
                checked={payloadSource === 'library'}
                onChange={(e) => setPayloadSource(e.target.value)}
              />
              Use Preset Payloads (selected attack)
            </label>
            <label>
              <input
                type="radio"
                name="payloadSource"
                value="file"
                checked={payloadSource === 'file'}
                onChange={(e) => setPayloadSource(e.target.value)}
              />
              Upload custom payload file (any type)
            </label>
            {/* accept any file type for greater flexibility */}
            <input type="file" accept="*/*" onChange={onFileChange} disabled={payloadSource !== 'file'} />
            {fileName && (
              <div className="file-preview">Selected file: <code>{fileName}</code></div>
            )}

            <label>
              <input
                type="radio"
                name="payloadSource"
                value="text"
                checked={payloadSource === 'text'}
                onChange={(e) => setPayloadSource(e.target.value)}
              />
              Type payload(s) (one per line)
            </label>
            <textarea
              rows={3}
              placeholder="<script>alert(1)</script>\n' OR '1'='1"
              value={textPayload}
              onChange={(e) => setTextPayload(e.target.value)}
              disabled={payloadSource !== 'text'}
            />

            <label title={ollamaAvailable ? 'Ollama detected on 127.0.0.1:11434' : 'Start Ollama: `ollama serve` and ensure a model like llama3 is pulled'}>
              <input
                type="radio"
                name="payloadSource"
                value="llm"
                checked={payloadSource === 'llm'}
                onChange={(e) => setPayloadSource(e.target.value)}
                disabled={!ollamaAvailable}
              />
              LLM suggestion {ollamaAvailable ? '' : '(Ollama not available)'}
            </label>
            <div className="llm-row">
              <button className="btn-small" onClick={fetchLlmSuggestion} disabled={!ollamaAvailable || llmLoading}>
                {llmLoading ? '⏳ Generating…' : '✨ Generate with LLM'}
              </button>
              <textarea
                rows={2}
                placeholder="Generated payload will appear here"
                value={llmPayload}
                readOnly
              />
            </div>
            {!ollamaAvailable && (
              <div className="llm-hint">
                Ollama not reachable at {ollamaUrl}. Ensure "ollama serve" is running and a model (e.g., {ollamaModel}) is pulled.
                {ollamaError && <div className="llm-error">Last error: {ollamaError}</div>}
              </div>
            )}
          </div>
        </div>
      )}

      {activeTab === 'Recon' && (
        <div className="recon-panel">
          <h3>🛰️ Page Recon</h3>
          <div className="controls">
            <button onClick={runRecon} disabled={reconLoading} className="btn-primary">
              {reconLoading ? 'Reading...' : 'Run Passive Recon'}
            </button>
            <button onClick={exportPageSource} className="btn-secondary">Export Source</button>
          </div>

          {!recon && <div className="hint">Run passive recon to read the loaded page (no requests sent).</div>}

          {recon && (
            <div className="recon-results">
              <div className="recon-section">
                <h4>Overview</h4>
                <div className="muted">Title: {recon.title || '(none)'}</div>
                {recon.frameworks?.length > 0 && (
                  <div>Frameworks: {recon.frameworks.map((f) => <span key={f} className="tag tag-fw">{f}</span>)}</div>
                )}
                <div className="muted">Forms: {recon.forms?.length || 0} · Links: {recon.links?.length || 0} · Buttons: {recon.buttonCount || 0}</div>
              </div>

              {recon.forms?.length > 0 && (
                <div className="recon-section">
                  <h4>Forms</h4>
                  {recon.forms.map((f, i) => (
                    <div key={i} className="muted">{f.method.toUpperCase()} {f.action || '(self)'} — {f.fieldCount} field(s)</div>
                  ))}
                </div>
              )}

              {(recon.cookieNames?.length > 0 || recon.localStorageKeys?.length > 0 || recon.sessionStorageKeys?.length > 0) && (
                <div className="recon-section">
                  <h4>Storage (names only)</h4>
                  {recon.cookieNames?.length > 0 && <div className="muted">Cookies: {recon.cookieNames.join(', ')}</div>}
                  {recon.localStorageKeys?.length > 0 && <div className="muted">localStorage: {recon.localStorageKeys.join(', ')}</div>}
                  {recon.sessionStorageKeys?.length > 0 && <div className="muted">sessionStorage: {recon.sessionStorageKeys.join(', ')}</div>}
                </div>
              )}

              {recon.comments?.length > 0 && (
                <div className="recon-section">
                  <h4>HTML Comments ({recon.comments.length})</h4>
                  <pre className="history-payload">{recon.comments.slice(0, 10).join('\n')}</pre>
                </div>
              )}

              <div className="recon-section">
                <h4>Discovered Endpoints ({recon.endpoints?.length || 0})</h4>
                {(!recon.endpoints || recon.endpoints.length === 0) && <div className="muted">None found in inline scripts.</div>}
                {recon.endpoints?.map((ep, i) => (
                  <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
                    <code style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{ep}</code>
                    <button className="btn-small" onClick={() => probeEndpoint(ep)}>Probe</button>
                  </div>
                ))}
              </div>

              <div className="recon-section">
                <h4>Active Recon</h4>
                <p style={{ fontSize: 12, margin: '4px 0 8px' }}>
                  Fetches robots.txt, sitemap.xml, security.txt. Honors allowlist, dry-run and rate limits.
                </p>
                <button className="btn-secondary" onClick={() => runActiveRecon(false)}>Fetch Recon Files</button>
                {activeReconResult && activeReconResult.results && (
                  <div className="recon-section">
                    {activeReconResult.results.map((r, i) => (
                      <div key={i} className="muted">{r.status || '—'} {r.url} {r.error ? `(${r.error})` : ''}</div>
                    ))}
                  </div>
                )}
                {activeReconResult && activeReconResult.dryRun && (
                  <div className="recon-section">
                    {activeReconResult.wouldFetch.map((u, i) => (
                      <div key={i} className="muted">🔒 would fetch: {u}</div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {activeTab === 'History' && (
        <div className="history-panel">
          <h3>Payload History</h3>
          {payloadHistory.length === 0 ? (
            <div className="hint">No history yet. Run tests to save payloads here.</div>
          ) : (
            <div className="history-list">
              {payloadHistory.map((h, idx) => (
                <div key={idx} className="history-item">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                      <strong>{h.vuln || 'custom'}</strong>
                      <div className="muted">{new Date(h.timestamp).toLocaleString()}</div>
                      <div className="muted">Source: {h.payloadSource}</div>
                    </div>
                    <div style={{ display: 'flex', gap: 8 }}>
                      <button className="btn-small" onClick={() => insertHistoryEntry(h)}>Insert</button>
                      <button className="btn-small" onClick={() => copyHistoryEntry(h)}>Copy</button>
                      <button className="btn-remove" onClick={() => deleteHistoryEntry(idx)}>Delete</button>
                    </div>
                  </div>
                  <pre className="history-payload">{(h.payloads || []).slice(0, 5).join('\n')}</pre>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {activeTab === 'Settings' && (
        <div className="settings-panel">
          <h3>Configuration</h3>

          <div className="setting-item">
            <label>
              <input
                type="checkbox"
                checked={dryRunMode}
                onChange={toggleDryRun}
              />
              Dry Run Mode (Safe - No actual changes)
            </label>
          </div>

          <div className="setting-item">
            <h4>Host Allowlist</h4>
            <div className="allowlist-input">
              <input
                type="text"
                value={newHost}
                onChange={(e) => setNewHost(e.target.value)}
                placeholder="Enter hostname (e.g., localhost)"
              />
              <button onClick={addToAllowlist} className="btn-small">Add</button>
            </div>
            <ul className="allowlist">
              {allowlist.map((host, idx) => (
                <li key={idx}>
                  {host}
                  <button onClick={() => removeFromAllowlist(host)} className="btn-remove">×</button>
                </li>
              ))}
            </ul>
          </div>

          <div className="setting-item">
            <h4>Audit Log ({auditLog.length} entries)</h4>
            <button onClick={exportAuditLog} className="btn-small">
              Export Log
            </button>
          </div>

          <div className="setting-item">
            <h4>LLM (Ollama) Advanced</h4>
            <div className="allowlist-input">
              <input
                type="text"
                value={ollamaUrl}
                onChange={(e) => setOllamaUrl(e.target.value)}
                placeholder="http://127.0.0.1:11434"
              />
              <input
                type="text"
                value={ollamaModel}
                onChange={(e) => setOllamaModel(e.target.value)}
                placeholder="llama3.2:1b"
              />
              <button
                className="btn-small"
                onClick={async () => {
                  if (!ollama) return;
                  ollama.setBaseUrl(ollamaUrl);
                  ollama.setModel(ollamaModel);
                  const ok = await ollama.checkAvailability();
                  setOllamaAvailable(ok);
                  setOllamaError(ollama.getLastError?.() || '');
                  setOllamaStatus(ok ? 'Connected' : '');
                }}
              >
                Test Connection
              </button>
            </div>
            {ollamaAvailable && ollamaStatus && (
              <div className="llm-ok">{ollamaStatus}</div>
            )}
            {!ollamaAvailable && ollamaError && (
              <div className="llm-error">
                {ollamaError}
                {ollamaError.includes('403') && (
                  <div style={{ marginTop: 6, fontSize: 12, lineHeight: 1.4 }}>
                    <strong>403 Forbidden:</strong> Ollama rejected the extension origin.<br />
                    Fix A (recommended): Restart Ollama with an origin allowlist including <code>chrome-extension://{extensionId}</code><br />
                    <code style={{ display: 'block', whiteSpace: 'pre-wrap', background: '#eef2ff', padding: '4px 6px', borderRadius: 4, marginTop: 4 }}>
                      {`# Example (macOS/Linux shell):
  export OLLAMA_ORIGINS='http://127.0.0.1 http://localhost chrome-extension://${extensionId}'
  ollama serve`}
                    </code>
                    Fix B: Use the local proxy (see below) and set base URL to <code>http://127.0.0.1:5000</code>.
                  </div>
                )}
              </div>
            )}
            {/* Proxy helper guidance */}
            <div style={{ marginTop: 16 }}>
              <h4 style={{ margin: '8px 0' }}>Proxy Workaround</h4>
              <p style={{ fontSize: 12, margin: '4px 0 8px' }}>If you cannot modify Ollama origins, run the provided proxy (scripts/ollama-proxy.js) then set Base URL to <code>http://127.0.0.1:5000</code>. It strips the Origin header so POST /api/generate succeeds.</p>
              {ollamaError.includes('403') && (
                <p style={{ fontSize: 12, color: '#b00020' }}>403 detected – proxy workaround is available. See project scripts folder.</p>
              )}
            </div>
          </div>
        </div>
      )}

      {confirmAction && (
        <div className="modal-overlay">
          <div className="modal">
            <h3>Confirm Action</h3>
            <p>{confirmAction.message}</p>
            <div className="modal-actions">
              <button onClick={handleConfirm} className="btn-confirm">
                Confirm
              </button>
              <button onClick={handleCancel} className="btn-cancel">
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Popup;
