import React, { useState, useEffect } from 'react';
import './Popup.css';
import { DEFAULT_VULNS } from '../../utils/payloads';
import OllamaPayloadAssistant from '../../utils/ollamaIntegration';

const ShieldCheckIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    <polyline points="9 12 11 14 15 10" />
  </svg>
);

const ScanIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
  </svg>
);

const RocketIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <path d="M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09zM12 15l-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6 11A22.35 22.35 0 0 1 12 15z" />
  </svg>
);

const CheckIcon = () => (
  <svg width="10" height="10" viewBox="0 0 10 8" fill="none">
    <polyline points="1,4 3.5,6.5 9,1" stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

const TYPE_STYLES = {
  input:    { dot: '#6366f1', bg: '#eef2ff', color: '#4338ca', label: 'INPUT' },
  textarea: { dot: '#8b5cf6', bg: '#f5f3ff', color: '#6d28d9', label: 'TEXTAREA' },
  select:   { dot: '#0ea5e9', bg: '#f0f9ff', color: '#0369a1', label: 'SELECT' },
  file:     { dot: '#14b8a6', bg: '#f0fdfa', color: '#0f766e', label: 'FILE' },
};
const getTypeStyle = (type) =>
  TYPE_STYLES[type] || { dot: '#94a3b8', bg: '#f8fafc', color: '#475569', label: (type || 'FIELD').toUpperCase() };

const Popup = () => {
  const [elements, setElements] = useState([]);
  const [selectedIds, setSelectedIds] = useState(new Set());
  const [loading, setLoading] = useState(false);
  const [currentUrl, setCurrentUrl] = useState('');
  const [allowlist, setAllowlist] = useState([]);
  const [dryRunMode, setDryRunMode] = useState(true);
  const [auditLog, setAuditLog] = useState([]);
  const [newHost, setNewHost] = useState('');
  const [confirmAction, setConfirmAction] = useState(null);
  const [selectedVuln, setSelectedVuln] = useState(DEFAULT_VULNS[0].key);
  const [payloadSource, setPayloadSource] = useState('library');
  const [filePayload, setFilePayload] = useState('');
  const [fileName, setFileName] = useState('');
  const [textPayload, setTextPayload] = useState('');
  const [fileData, setFileData] = useState(null);
  const [llmPayload, setLlmPayload] = useState('');
  const [llmLoading, setLlmLoading] = useState(false);
  const [ollamaAvailable, setOllamaAvailable] = useState(false);
  const [ollama] = useState(() => { try { return new OllamaPayloadAssistant(); } catch { return null; } });
  const [ollamaUrl, setOllamaUrl] = useState('http://127.0.0.1:11434');
  const [ollamaModel, setOllamaModel] = useState('llama3');
  const [ollamaError, setOllamaError] = useState('');
  const [ollamaStatus, setOllamaStatus] = useState('');
  const [activeTab, setActiveTab] = useState('Scan');
  const [payloadHistory, setPayloadHistory] = useState([]);
  const extensionId = chrome?.runtime?.id || '<extension-id>';

  useEffect(() => {
    chrome.storage.local.get(['allowlist', 'dryRunMode', 'auditLog', 'payloadHistory'], (result) => {
      setAllowlist(result.allowlist || ['*']);
      setDryRunMode(result.dryRunMode !== undefined ? result.dryRunMode : true);
      setAuditLog(result.auditLog || []);
      setPayloadHistory(result.payloadHistory || []);
    });
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) setCurrentUrl(tabs[0].url);
    });
    (async () => {
      try {
        if (ollama) {
          ollama.setBaseUrl(ollamaUrl);
          ollama.setModel(ollamaModel);
          if (await ollama.checkAvailability()) {
            setOllamaAvailable(true);
            setOllamaError('');
          } else {
            setOllamaAvailable(false);
            setOllamaError(ollama?.getLastError?.() || '');
          }
        }
      } catch { setOllamaAvailable(false); }
    })();
  }, []);

  const isHostAllowed = (url) => {
    try {
      const hostname = new URL(url).hostname;
      if (allowlist.includes('*')) return true;
      return allowlist.some(allowed => hostname.includes(allowed));
    } catch { return false; }
  };

  const addToAuditLog = (action, elementInfo, result) => {
    const entry = { timestamp: new Date().toISOString(), action, url: currentUrl, element: elementInfo, result, dryRun: dryRunMode };
    const newLog = [entry, ...auditLog].slice(0, 100);
    setAuditLog(newLog);
    chrome.storage.local.set({ auditLog: newLog });
  };

  const toggleSelection = (uid) => setSelectedIds(prev => {
    const s = new Set(prev);
    s.has(uid) ? s.delete(uid) : s.add(uid);
    return s;
  });
  const selectAll = () => setSelectedIds(new Set(elements.map(e => e.uniqueId)));
  const clearSelection = () => setSelectedIds(new Set());
  const selectFilesOnly = () => setSelectedIds(new Set(elements.filter(e => e.type === 'file').map(e => e.uniqueId)));

  const scanPage = async () => {
    if (!isHostAllowed(currentUrl)) { alert('⚠️ Host not in allowlist. Add it in Settings first.'); return; }
    setLoading(true);
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      const pingOk = await new Promise(resolve => {
        chrome.tabs.sendMessage(tab.id, { action: 'ping' }, resp => resolve(Boolean(resp?.ok)));
        setTimeout(() => resolve(false), 500);
      });
      if (!pingOk) { alert('Content script unavailable. Reload the page and retry.'); setLoading(false); return; }
      chrome.tabs.sendMessage(tab.id, { action: 'scanPage' }, response => {
        if (chrome.runtime.lastError) { alert('Error: Refresh the page and try again.'); setLoading(false); return; }
        if (response?.success) { setElements(response.elements); addToAuditLog('SCAN', { count: response.elements.length }, 'SUCCESS'); }
        setLoading(false);
      });
    } catch { setLoading(false); }
  };

  const confirmAndExecute = (action, element, callback) => {
    if (dryRunMode) { alert(`🔒 DRY RUN: Would execute ${action} on ${element.name || element.type}`); addToAuditLog(action, element, 'DRY_RUN'); return; }
    setConfirmAction({ message: `Execute ${action} on "${element.name || element.type}"?`, onConfirm: callback });
  };
  const handleConfirm = () => { if (confirmAction?.onConfirm) confirmAction.onConfirm(); setConfirmAction(null); };
  const handleCancel = () => setConfirmAction(null);

  const readFileAsBase64 = (file) => new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const bytes = new Uint8Array(reader.result);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
        resolve({ base64: btoa(binary), mime: file.type || 'application/octet-stream', name: file.name || 'upload.bin', arrayBuffer: reader.result });
      } catch (e) { reject(e); }
    };
    reader.onerror = reject;
    reader.readAsArrayBuffer(file);
  });

  const onFileChange = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      setFileName(file.name || '');
      const b = await readFileAsBase64(file);
      setFileData({ base64: b.base64, mime: b.mime, name: b.name });
      try { setFilePayload(new TextDecoder('utf-8').decode(new Uint8Array(b.arrayBuffer))); } catch { setFilePayload(''); }
      setPayloadSource('file');
    } catch { alert('Failed to read file'); }
  };

  const fetchLlmSuggestion = async () => {
    if (!ollama) return;
    const vuln = DEFAULT_VULNS.find(v => v.key === selectedVuln);
    setLlmLoading(true);
    try {
      const s = await ollama.generatePayload({ elementType: 'input', elementName: '*', testType: 'Payload Generation', vulnerability: vuln?.label || selectedVuln });
      setLlmPayload(s.payload || '');
      setPayloadSource('llm');
    } catch (e) {
      const msg = ollama?.getLastError?.() || e?.message || 'LLM unavailable.';
      alert(msg); setOllamaError(msg);
    } finally { setLlmLoading(false); }
  };

  const runVulnTest = async () => {
    const vuln = DEFAULT_VULNS.find(v => v.key === selectedVuln);
    if (!vuln) return;
    let payloads = vuln.payloads;
    if (payloadSource === 'file' && filePayload.trim()) payloads = filePayload.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    else if (payloadSource === 'text' && textPayload.trim()) payloads = textPayload.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    else if (payloadSource === 'llm' && llmPayload.trim()) payloads = [llmPayload.trim()];

    const executeAction = async () => {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      const pingOk = await new Promise(resolve => {
        chrome.tabs.sendMessage(tab.id, { action: 'ping' }, resp => resolve(Boolean(resp?.ok)));
        setTimeout(() => resolve(false), 500);
      });
      if (!pingOk) { alert('Content script unavailable. Reload the page.'); return; }
      const targetIds = selectedIds?.size > 0 ? Array.from(selectedIds) : elements.map(e => e.uniqueId);
      if (payloadSource === 'file' && fileData) {
        chrome.tabs.sendMessage(tab.id, { action: 'attachFile', fileData, uniqueIds: targetIds }, response => {
          if (response?.success) {
            const ok = response.results.filter(r => r.success).length;
            alert(`✅ File attached to ${ok}/${response.results.length} fields`);
            addToAuditLog('ATTACH_FILE', { file: fileData.name, results: response.results }, 'SUCCESS');
            savePayloadHistory({ timestamp: new Date().toISOString(), vuln: vuln.key, payloadSource, payloads: [fileData.name], targets: targetIds });
          } else { alert('❌ Failed to attach file'); addToAuditLog('ATTACH_FILE', { file: fileData.name }, 'FAILED'); }
        });
      } else {
        chrome.tabs.sendMessage(tab.id, { action: 'executeVulnTest', vulnKey: vuln.key, payloads, uniqueIds: targetIds }, response => {
          if (response?.success) {
            const ok = response.results.filter(r => r.success).length;
            alert(`✅ ${vuln.label} applied to ${ok}/${response.results.length} fields`);
            addToAuditLog('VULN_TEST', { vuln: vuln.key, results: response.results }, 'SUCCESS');
            savePayloadHistory({ timestamp: new Date().toISOString(), vuln: vuln.key, payloadSource, payloads, targets: targetIds });
          } else { alert('❌ Failed to execute test'); addToAuditLog('VULN_TEST', { vuln: vuln.key }, 'FAILED'); }
        });
      }
    };
    confirmAndExecute(`${vuln.label} Test`, { name: vuln.key, type: 'vuln' }, executeAction);
  };

  const addToAllowlist = () => {
    if (newHost && !allowlist.includes(newHost)) {
      const updated = [...allowlist, newHost];
      setAllowlist(updated); chrome.storage.local.set({ allowlist: updated }); setNewHost('');
    }
  };
  const removeFromAllowlist = (host) => {
    const updated = allowlist.filter(h => h !== host);
    setAllowlist(updated); chrome.storage.local.set({ allowlist: updated });
  };
  const toggleDryRun = () => { const v = !dryRunMode; setDryRunMode(v); chrome.storage.local.set({ dryRunMode: v }); };
  const exportAuditLog = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(auditLog, null, 2)], { type: 'application/json' }));
    Object.assign(document.createElement('a'), { href: url, download: `secureinspect_audit_${Date.now()}.json` }).click();
  };

  const savePayloadHistory = (entry) => {
    setPayloadHistory(prev => {
      const next = [entry, ...prev].slice(0, 50);
      try { chrome.storage.local.set({ payloadHistory: next }); } catch {}
      return next;
    });
  };
  const insertHistoryEntry = (entry) => {
    if (!entry?.payloads) return;
    setPayloadSource('text'); setTextPayload(entry.payloads.join('\n')); setActiveTab('Payloads');
  };
  const copyHistoryEntry = async (entry) => {
    if (!entry?.payloads) return;
    try { await navigator.clipboard.writeText(entry.payloads.join('\n')); } catch { alert('Copy failed'); }
  };
  const deleteHistoryEntry = (i) => {
    setPayloadHistory(prev => {
      const c = [...prev]; c.splice(i, 1);
      try { chrome.storage.local.set({ payloadHistory: c }); } catch {}
      return c;
    });
  };

  const TABS = [
    { key: 'Scan', label: 'Scan' },
    { key: 'Payloads', label: 'Payloads' },
    { key: 'History', label: 'History' },
    { key: 'Settings', label: 'Settings' },
  ];

  const hostAllowed = isHostAllowed(currentUrl);

  return (
    <div className="si-root">

      <header className="si-header">
        <div className="si-header-brand">
          <div className="si-logo-wrap">
            <ShieldCheckIcon />
          </div>
          <div>
            <div className="si-app-name">SecureInspect</div>
            <div className="si-app-sub">Form Security Tester</div>
          </div>
        </div>
        <div className={`si-mode-badge ${dryRunMode ? 'si-mode-dry' : 'si-mode-live'}`}>
          <span className="si-mode-dot" />
          {dryRunMode ? 'DRY RUN' : 'LIVE'}
        </div>
      </header>

      {!hostAllowed && (
        <div className="si-banner-warning">
          <span>⚠</span>
          <span>
            Host not in allowlist —{' '}
            <button className="si-banner-link" onClick={() => setActiveTab('Settings')}>
              add it in Settings
            </button>
          </span>
        </div>
      )}

      <nav className="si-tab-nav">
        {TABS.map(tab => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={`si-tab ${activeTab === tab.key ? 'si-tab--active' : ''}`}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      <main className="si-main">

        {activeTab === 'Scan' && (
          <div className="si-pane">
            <div className="si-action-bar">
              <button onClick={scanPage} disabled={loading} className="si-btn-primary">
                {loading ? <><span className="si-spinner" />Scanning…</> : <><ScanIcon />Scan Page</>}
              </button>
              <div className="si-vdivider" />
              <select value={selectedVuln} onChange={e => setSelectedVuln(e.target.value)} className="si-select">
                {DEFAULT_VULNS.map(v => <option key={v.key} value={v.key}>{v.label}</option>)}
              </select>
              <button onClick={runVulnTest} disabled={!hostAllowed} className="si-btn-accent">
                <RocketIcon />Run Test
              </button>
            </div>

            {elements.length > 0 && (
              <div className="si-stats-bar">
                <span className="si-stats-label">
                  {elements.length} element{elements.length !== 1 ? 's' : ''}
                  {selectedIds.size > 0 && <span className="si-stats-sel"> · {selectedIds.size} selected</span>}
                </span>
                <div className="si-stats-chips">
                  <button onClick={selectAll} className="si-chip">All</button>
                  <button onClick={clearSelection} className="si-chip">Clear</button>
                  <button onClick={selectFilesOnly} className="si-chip">Files</button>
                </div>
              </div>
            )}

            {elements.length === 0 && !loading && (
              <div className="si-empty">
                <div className="si-empty-icon">🔍</div>
                <div className="si-empty-title">Ready to scan</div>
                <div className="si-empty-sub">Click "Scan Page" to discover all form inputs on this page</div>
              </div>
            )}

            <div className="si-element-list">
              {elements.map((el, idx) => {
                const ts = getTypeStyle(el.type);
                const selected = selectedIds.has(el.uniqueId);
                return (
                  <div
                    key={idx}
                    className={`si-element-card ${selected ? 'si-element-card--selected' : ''}`}
                    onClick={() => toggleSelection(el.uniqueId)}
                  >
                    <div className="si-element-row">
                      <div className={`si-checkbox ${selected ? 'si-checkbox--on' : ''}`}>
                        {selected && <CheckIcon />}
                      </div>
                      <div className="si-type-dot" style={{ background: ts.dot }} />
                      <span className="si-type-badge" style={{ background: ts.bg, color: ts.color }}>
                        {ts.label}{el.subType ? `·${el.subType}` : ''}
                      </span>
                      <span className="si-el-name">
                        {el.name || el.id || <em>unnamed</em>}
                      </span>
                      {el.required && <span className="si-badge-req">Required</span>}
                    </div>
                    {(el.id || el.placeholder) && (
                      <div className="si-el-meta">
                        {el.id && <span>id: <code>{el.id}</code></span>}
                        {el.placeholder && <span className="si-el-placeholder">placeholder: <em>{el.placeholder}</em></span>}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {activeTab === 'Payloads' && (
          <div className="si-pane">
            <div className="si-pane-title">Payload Source</div>

            <label className={`si-source-card ${payloadSource === 'library' ? 'si-source-card--active' : ''}`}>
              <input type="radio" name="ps" value="library" checked={payloadSource === 'library'} onChange={e => setPayloadSource(e.target.value)} className="si-radio" />
              <div className="si-source-body">
                <div className="si-source-title">Preset Library</div>
                <div className="si-source-desc">OWASP-curated payloads for the selected attack type</div>
              </div>
            </label>

            <label className={`si-source-card ${payloadSource === 'file' ? 'si-source-card--active' : ''}`}>
              <input type="radio" name="ps" value="file" checked={payloadSource === 'file'} onChange={e => setPayloadSource(e.target.value)} className="si-radio" />
              <div className="si-source-body">
                <div className="si-source-title">Upload File</div>
                <div className="si-source-desc">Any file type — attach to file inputs or use as text payloads</div>
                <input type="file" accept="*/*" onChange={onFileChange} className="si-file-input" />
                {fileName && (
                  <div className="si-file-preview">
                    <span>📎</span>
                    <code>{fileName}</code>
                  </div>
                )}
              </div>
            </label>

            <label className={`si-source-card ${payloadSource === 'text' ? 'si-source-card--active' : ''}`}>
              <input type="radio" name="ps" value="text" checked={payloadSource === 'text'} onChange={e => setPayloadSource(e.target.value)} className="si-radio" />
              <div className="si-source-body">
                <div className="si-source-title">Manual Entry</div>
                <div className="si-source-desc">Enter custom payloads, one per line</div>
                <textarea
                  rows={3}
                  placeholder={"<script>alert(1)</script>\n' OR '1'='1"}
                  value={textPayload}
                  onChange={e => setTextPayload(e.target.value)}
                  disabled={payloadSource !== 'text'}
                  className="si-textarea"
                />
              </div>
            </label>

            <label className={`si-source-card ${!ollamaAvailable ? 'si-source-card--disabled' : payloadSource === 'llm' ? 'si-source-card--active' : ''}`}>
              <input type="radio" name="ps" value="llm" checked={payloadSource === 'llm'} onChange={e => setPayloadSource(e.target.value)} disabled={!ollamaAvailable} className="si-radio" />
              <div className="si-source-body">
                <div className="si-source-title-row">
                  <span className="si-source-title">LLM — Ollama</span>
                  <span className={`si-status-pill ${ollamaAvailable ? 'si-status-pill--on' : 'si-status-pill--off'}`}>
                    {ollamaAvailable ? 'Online' : 'Offline'}
                  </span>
                </div>
                <div className="si-source-desc">AI-generated context-aware payloads via local Ollama</div>
                {ollamaAvailable && (
                  <div className="si-llm-row">
                    <button onClick={fetchLlmSuggestion} disabled={llmLoading} className="si-btn-sm-primary">
                      {llmLoading ? '⏳ Generating…' : '✨ Generate'}
                    </button>
                    {llmPayload && (
                      <textarea rows={2} value={llmPayload} readOnly className="si-textarea si-textarea--compact" />
                    )}
                  </div>
                )}
                {!ollamaAvailable && (
                  <div className="si-hint si-hint--warn">
                    Ollama not reachable at <code>{ollamaUrl}</code>. Run{' '}
                    <code>ollama serve</code> with model <code>{ollamaModel}</code>.
                    {ollamaError && <div className="si-hint-detail">{ollamaError}</div>}
                  </div>
                )}
              </div>
            </label>
          </div>
        )}

        {activeTab === 'History' && (
          <div className="si-pane">
            <div className="si-pane-title">Payload History</div>
            {payloadHistory.length === 0 ? (
              <div className="si-empty">
                <div className="si-empty-icon">📋</div>
                <div className="si-empty-title">No history yet</div>
                <div className="si-empty-sub">Run tests to save payloads here for quick reuse</div>
              </div>
            ) : (
              <div className="si-history-list">
                {payloadHistory.map((h, idx) => (
                  <div key={idx} className="si-history-card">
                    <div className="si-history-top">
                      <div className="si-history-tags">
                        <span className="si-history-vuln">{h.vuln || 'custom'}</span>
                        <span className="si-history-src">{h.payloadSource}</span>
                        <span className="si-history-time">{new Date(h.timestamp).toLocaleString()}</span>
                      </div>
                      <div className="si-history-actions">
                        <button onClick={() => insertHistoryEntry(h)} className="si-chip si-chip--primary">Insert</button>
                        <button onClick={() => copyHistoryEntry(h)} className="si-chip">Copy</button>
                        <button onClick={() => deleteHistoryEntry(idx)} className="si-chip si-chip--danger">Delete</button>
                      </div>
                    </div>
                    <pre className="si-history-payload">
                      {(h.payloads || []).slice(0, 3).join('\n')}
                      {(h.payloads || []).length > 3 && `\n… +${h.payloads.length - 3} more`}
                    </pre>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === 'Settings' && (
          <div className="si-pane">
            <div className="si-pane-title">Settings</div>

            <div className="si-card">
              <div className="si-card-row">
                <div>
                  <div className="si-card-label">Dry Run Mode</div>
                  <div className="si-card-desc">Simulate tests without modifying the page</div>
                </div>
                <button onClick={toggleDryRun} className={`si-toggle ${dryRunMode ? 'si-toggle--on' : 'si-toggle--off'}`}>
                  <span className={`si-toggle-thumb ${dryRunMode ? 'si-toggle-thumb--on' : ''}`} />
                </button>
              </div>
              {!dryRunMode && (
                <div className="si-alert si-alert--danger">
                  ⚠ Live mode — payloads will be injected into real page inputs
                </div>
              )}
            </div>

            <div className="si-card">
              <div className="si-card-label">Host Allowlist</div>
              <div className="si-card-desc">Only test hosts in this list (use * for all)</div>
              <div className="si-allowlist-input">
                <input
                  type="text"
                  value={newHost}
                  onChange={e => setNewHost(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && addToAllowlist()}
                  placeholder="e.g. localhost or dvwa"
                  className="si-input"
                />
                <button onClick={addToAllowlist} className="si-btn-primary si-btn--sm">Add</button>
              </div>
              <div className="si-allowlist">
                {allowlist.map((host, idx) => (
                  <div key={idx} className="si-allowlist-item">
                    <code className="si-host-code">{host}</code>
                    <button onClick={() => removeFromAllowlist(host)} className="si-remove-btn">✕</button>
                  </div>
                ))}
              </div>
            </div>

            <div className="si-card si-card-row">
              <div>
                <div className="si-card-label">Audit Log</div>
                <div className="si-card-desc">{auditLog.length} entries recorded</div>
              </div>
              <button onClick={exportAuditLog} className="si-btn-outline">
                📥 Export
              </button>
            </div>

            <div className="si-card">
              <div className="si-card-row">
                <div>
                  <div className="si-card-label">Ollama LLM</div>
                  <div className="si-card-desc">Local AI for payload generation</div>
                </div>
                <span className={`si-status-pill ${ollamaAvailable ? 'si-status-pill--on' : 'si-status-pill--off'}`}>
                  {ollamaAvailable ? '● Online' : '○ Offline'}
                </span>
              </div>
              <div className="si-ollama-fields">
                <input type="text" value={ollamaUrl} onChange={e => setOllamaUrl(e.target.value)} placeholder="http://127.0.0.1:11434" className="si-input si-input--mono" />
                <input type="text" value={ollamaModel} onChange={e => setOllamaModel(e.target.value)} placeholder="llama3" className="si-input si-input--mono" />
                <button
                  className="si-btn-outline"
                  onClick={async () => {
                    if (!ollama) return;
                    ollama.setBaseUrl(ollamaUrl);
                    ollama.setModel(ollamaModel);
                    const ok = await ollama.checkAvailability();
                    setOllamaAvailable(ok);
                    setOllamaError(ollama.getLastError?.() || '');
                    setOllamaStatus(ok ? '✅ Connected successfully' : '');
                  }}
                >
                  Test Connection
                </button>
              </div>
              {ollamaAvailable && ollamaStatus && (
                <div className="si-hint si-hint--success">{ollamaStatus}</div>
              )}
              {!ollamaAvailable && ollamaError && (
                <div className="si-hint si-hint--error">
                  <strong>Connection failed:</strong> {ollamaError}
                  {ollamaError.includes('403') && (
                    <div className="si-403-guide">
                      <div><strong>Fix:</strong> Allow the extension origin in Ollama:</div>
                      <code className="si-code-block">
                        {`OLLAMA_ORIGINS='chrome-extension://${extensionId}' ollama serve`}
                      </code>
                      <div>Or use the proxy and set URL to <code>http://127.0.0.1:5000</code>.</div>
                    </div>
                  )}
                </div>
              )}
              <details className="si-details">
                <summary className="si-details-summary">Proxy workaround</summary>
                <p className="si-details-body">
                  Run <code>node scripts/ollama-proxy.js</code> then set Base URL to{' '}
                  <code>http://127.0.0.1:5000</code>. The proxy strips the Origin header so POST requests succeed.
                </p>
              </details>
            </div>
          </div>
        )}
      </main>

      {confirmAction && (
        <div className="si-modal-overlay">
          <div className="si-modal">
            <div className="si-modal-icon">⚠️</div>
            <h3 className="si-modal-title">Confirm Action</h3>
            <p className="si-modal-msg">{confirmAction.message}</p>
            <div className="si-modal-btns">
              <button onClick={handleConfirm} className="si-btn-primary si-modal-btn">Confirm</button>
              <button onClick={handleCancel} className="si-btn-ghost si-modal-btn">Cancel</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Popup;
