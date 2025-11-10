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
  const [ollamaModel, setOllamaModel] = useState('llama3');
  const [ollamaError, setOllamaError] = useState('');
  const [ollamaStatus, setOllamaStatus] = useState('');
  const [activeTab, setActiveTab] = useState('Scan'); // 'Scan' | 'Payloads' | 'History' | 'Settings'
  const [payloadHistory, setPayloadHistory] = useState([]);
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

  const scanPage = async () => {
    if (!isHostAllowed(currentUrl)) {
      alert('⚠️ Current host is not in allowlist! Add it in settings first.');
      return;
    }

    setLoading(true);
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      // quick ping to ensure content script is available
      const pingOk = await new Promise((resolve) => {
        chrome.tabs.sendMessage(tab.id, { action: 'ping' }, (resp) => {
          resolve(Boolean(resp && resp.ok));
        });
        setTimeout(() => resolve(false), 500);
      });
      if (!pingOk) {
        alert('Content script not available on this page. Try reloading the page and re-opening the popup.');
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
          addToAuditLog('SCAN', { count: response.elements.length }, 'SUCCESS');
        }
        setLoading(false);
      });
    } catch (error) {
      console.error('Scan error:', error);
      setLoading(false);
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
      const pingOk = await new Promise((resolve) => {
        chrome.tabs.sendMessage(tab.id, { action: 'ping' }, (resp) => resolve(Boolean(resp && resp.ok)));
        setTimeout(() => resolve(false), 500);
      });
      if (!pingOk) {
        alert('Content script not available on this page. Try reloading the page.');
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
    switch (type) {
      case 'input': return '📝';
      case 'textarea': return '📄';
      case 'select': return '📋';
      case 'file': return '📎';
      default: return '🔹';
    }
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

  return (
    <div className="sectest-container">
      <div className="header">
        <h2>🔒 SecTest Pro</h2>
        <div className="status-badge">
          {dryRunMode ? 'DRY RUN' : 'LIVE'}
        </div>
      </div>

      {!isHostAllowed(currentUrl) && (
        <div className="warning-banner">
          ⚠️ Host not allowed
        </div>
      )}

      <div className="tab-nav">
        <button className={"tab" + (activeTab === 'Scan' ? ' active' : '')} onClick={() => setActiveTab('Scan')}>🔍 Scan</button>
        <button className={"tab" + (activeTab === 'Payloads' ? ' active' : '')} onClick={() => setActiveTab('Payloads')}>🧰 Payloads</button>
        <button className={"tab" + (activeTab === 'History' ? ' active' : '')} onClick={() => setActiveTab('History')}>📜 History</button>
        <button className={"tab" + (activeTab === 'Settings' ? ' active' : '')} onClick={() => setActiveTab('Settings')}>⚙️ Settings</button>
      </div>

      {activeTab === 'Scan' && (
        <div>
          <div className="controls">
            <button onClick={scanPage} disabled={loading} className="btn-primary">
              {loading ? '⏳ Scanning...' : '🔍 Scan Page'}
            </button>
            <button onClick={() => setActiveTab('Settings')} className="btn-secondary">
              ⚙️ Settings
            </button>
            <div className="vuln-runner">
              <select value={selectedVuln} onChange={(e) => setSelectedVuln(e.target.value)}>
                {DEFAULT_VULNS.map((v) => (
                  <option key={v.key} value={v.key}>{v.label}</option>
                ))}
              </select>
              <button onClick={runVulnTest} className="btn-secondary" disabled={!isHostAllowed(currentUrl)}>
                🚀 Run Test
              </button>
            </div>
          </div>

          <div className="elements-list">
            {elements.length > 0 && (
              <div className="stats">
                <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center'}}>
                  <div>Found {elements.length} form elements</div>
                  <div style={{display: 'flex', gap: 8}}>
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
                    style={{marginRight: 8}}
                    checked={selectedIds && selectedIds.has && selectedIds.has(element.uniqueId)}
                    onChange={() => toggleSelection(element.uniqueId)}
                    title="Select this field for payloads/attachments"
                  />
                  <span className="element-icon">{getElementIcon(element.type)}</span>
                  <span className="element-type">{element.type}</span>
                  <span className="element-name">{element.name || 'unnamed'}</span>
                </div>

                <div className="element-details">
                  {element.subType && <div>Type: {element.subType}</div>}
                  {element.id && <div>ID: {element.id}</div>}
                  {element.placeholder && <div>Placeholder: {element.placeholder}</div>}
                  {element.required && <div className="badge-required">Required</div>}
                </div>
              </div>
            ))}
          </div>
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

      {activeTab === 'History' && (
        <div className="history-panel">
          <h3>📜 Payload History</h3>
          {payloadHistory.length === 0 ? (
            <div className="hint">No history yet. Run tests to save payloads here.</div>
          ) : (
            <div className="history-list">
              {payloadHistory.map((h, idx) => (
                <div key={idx} className="history-item">
                  <div style={{display:'flex', justifyContent:'space-between', alignItems:'center'}}>
                    <div>
                      <strong>{h.vuln || 'custom'}</strong>
                      <div className="muted">{new Date(h.timestamp).toLocaleString()}</div>
                      <div className="muted">Source: {h.payloadSource}</div>
                    </div>
                    <div style={{display:'flex', gap:8}}>
                      <button className="btn-small" onClick={() => insertHistoryEntry(h)}>Insert</button>
                      <button className="btn-small" onClick={() => copyHistoryEntry(h)}>Copy</button>
                      <button className="btn-remove" onClick={() => deleteHistoryEntry(idx)}>Delete</button>
                    </div>
                  </div>
                  <pre className="history-payload">{(h.payloads || []).slice(0,5).join('\n')}</pre>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {activeTab === 'Settings' && (
        <div className="settings-panel">
          <h3>⚙️ Settings</h3>
          
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
              📥 Export Log
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
                placeholder="llama3"
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
                  setOllamaStatus(ok ? 'Connected ✅' : '');
                }}
              >
                🔁 Test Connection
              </button>
            </div>
            {ollamaAvailable && ollamaStatus && (
              <div className="llm-ok">{ollamaStatus}</div>
            )}
            {!ollamaAvailable && ollamaError && (
                <div className="llm-error">
                  {ollamaError}
                  {ollamaError.includes('403') && (
                    <div style={{marginTop:6, fontSize:12, lineHeight:1.4}}>
                      <strong>403 Forbidden:</strong> Ollama rejected the extension origin.<br/>
                      Fix A (recommended): Restart Ollama with an origin allowlist including <code>chrome-extension://{extensionId}</code><br/>
                      <code style={{display:'block',whiteSpace:'pre-wrap',background:'#eef2ff',padding:'4px 6px',borderRadius:4,marginTop:4}}>
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
            <div style={{marginTop:16}}>
              <h4 style={{margin:'8px 0'}}>Proxy Workaround</h4>
              <p style={{fontSize:12, margin:'4px 0 8px'}}>If you cannot modify Ollama origins, run the provided proxy (scripts/ollama-proxy.js) then set Base URL to <code>http://127.0.0.1:5000</code>. It strips the Origin header so POST /api/generate succeeds.</p>
              {ollamaError.includes('403') && (
                <p style={{fontSize:12, color:'#b00020'}}>403 detected – proxy workaround is available. See project scripts folder.</p>
              )}
            </div>
          </div>
        </div>
      )}

  <div className="elements-list">
        {elements.length > 0 && (
          <div className="stats">
            Found {elements.length} form elements
          </div>
        )}

        {elements.map((element, idx) => (
          <div key={idx} className="element-card">
            <div className="element-header">
              <span className="element-icon">{getElementIcon(element.type)}</span>
              <span className="element-type">{element.type}</span>
              <span className="element-name">{element.name || 'unnamed'}</span>
            </div>
            
            <div className="element-details">
              {element.subType && <div>Type: {element.subType}</div>}
              {element.id && <div>ID: {element.id}</div>}
              {element.placeholder && <div>Placeholder: {element.placeholder}</div>}
              {element.required && <div className="badge-required">Required</div>}
            </div>
          </div>
        ))}
      </div>

      {confirmAction && (
        <div className="modal-overlay">
          <div className="modal">
            <h3>⚠️ Confirm Action</h3>
            <p>{confirmAction.message}</p>
            <div className="modal-actions">
              <button onClick={handleConfirm} className="btn-confirm">
                ✓ Confirm
              </button>
              <button onClick={handleCancel} className="btn-cancel">
                ✗ Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Popup;
