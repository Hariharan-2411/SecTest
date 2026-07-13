import React, { useState, useEffect, useRef } from 'react';
import './Popup.css';
import { DEFAULT_VULNS } from '../../utils/payloads';
import {
  CHECKLIST,
  CHECKLIST_STATES,
  createChecklistProgress,
  summarizeProgress,
} from '../../utils/checklist';
import { evaluateScope, parseScopeText, scopeFromAllowlist } from '../../utils/scope';
import { summarizeInventory, emptyInventory } from '../../utils/inventory';
import { taintFindings } from '../../utils/taint';
import { sortFindings, summarizeFindings, dedupeFindings } from '../../utils/findings';
import { validateFindings, scoreFinding, canEscalateFinding, BANDS } from '../../utils/validate';
import { fallbackProse, explainConfidence } from '../../utils/validateProse';
import { proposeChains } from '../../utils/chains';
import { normalizePlan, mapStepToAction, isSafeStep, canEscalate, remainingBudget, DEFAULT_ESCALATION_BUDGET } from '../../utils/escalation';
import { assembleContext } from '../../utils/escalationContext';
import { buildReport, REPORT_PLATFORMS, SEVERITIES } from '../../utils/reportBuilder';
import {
  createProgram,
  createSubmission,
  summarizeSubmissions,
  summarizeByProgram,
  PLATFORMS,
  SUBMISSION_STATES,
} from '../../utils/programs';
import { WEBHOOK_PLATFORMS } from '../../utils/notify';
import * as ai from '../../utils/aiProvider';
import { DEFAULT_MODEL, decorate } from '../../utils/aiModels';
import { useToast } from '../../components/ToastProvider';
import { useTheme } from '../../hooks/useTheme';
import Login from './Login';
import AccountMenu from './AccountMenu';
import * as auth from '../../utils/auth';

const IconMoon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
  </svg>
);
const IconSun = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/>
    <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>
    <line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/>
    <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
  </svg>
);
const IconMonitor = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>
  </svg>
);
const IconAI = () => (
  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 2a2 2 0 0 1 2 2c0 .74-.4 1.39-1 1.73V7h1a7 7 0 0 1 7 7h1a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1h-1v1a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-1H2a1 1 0 0 1-1-1v-3a1 1 0 0 1 1-1h1a7 7 0 0 1 7-7h1V5.73c-.6-.34-1-.99-1-1.73a2 2 0 0 1 2-2z"/>
    <circle cx="9" cy="14" r="1" fill="currentColor" stroke="none"/>
    <circle cx="15" cy="14" r="1" fill="currentColor" stroke="none"/>
  </svg>
);

/* ─── AI Assistant icons ─────────────────────────────────────────── */
const IconCopy = () => (
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
  </svg>
);
const IconCheck = () => (
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="20 6 9 17 4 12"/>
  </svg>
);
const IconSend = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M22 2 11 13"/><path d="M22 2 15 22l-4-9-9-4 20-7z"/>
  </svg>
);
const IconTarget = () => (
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4.5"/><circle cx="12" cy="12" r="1" fill="currentColor" stroke="none"/>
  </svg>
);
const IconWand = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round">
    <path d="m3 21 9-9"/><path d="m14 7 3 3"/><path d="M15 4V2M15 10V8M20 5l-1.4 1.4M20 9l-1.4-1.4"/>
  </svg>
);
const IconBook = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round">
    <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/>
  </svg>
);
const IconScan = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round">
    <path d="M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2"/><line x1="7" y1="12" x2="17" y2="12"/>
  </svg>
);
const IconLayers = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round">
    <path d="m12 2 9 5-9 5-9-5 9-5z"/><path d="m3 12 9 5 9-5"/><path d="m3 17 9 5 9-5"/>
  </svg>
);
const IconUpload = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round">
    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>
  </svg>
);
const IconPencil = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4 12.5-12.5z"/>
  </svg>
);
const IconFile = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round">
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>
  </svg>
);

/* Copy-to-clipboard button with a transient "Copied" confirmation. */
const CopyButton = ({ text, className = 'ai-icon-btn', label = 'Copy', title = 'Copy' }) => {
  const [copied, setCopied] = useState(false);
  const copy = async (e) => {
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1400);
    } catch (_) {}
  };
  return (
    <button type="button" className={className} onClick={copy} title={copied ? 'Copied' : title} aria-label={title}>
      {copied ? <IconCheck /> : <IconCopy />}
      {label != null && <span>{copied ? 'Copied' : label}</span>}
    </button>
  );
};

/* Accessible on/off switch (role=switch). onChange receives the next boolean. */
const Toggle = ({ checked, onChange, label, tone = 'accent' }) => (
  <button
    type="button"
    role="switch"
    aria-checked={checked}
    aria-label={label}
    title={label}
    className={`iris-switch tone-${tone}${checked ? ' on' : ''}`}
    onClick={() => onChange(!checked)}
  >
    <span className="iris-switch-knob" />
  </button>
);

/* Fenced code block: language tag, copy, and "Use" → loads it into Payloads. */
const AiCodeBlock = ({ lang, code, onUse }) => (
  <div className="ai-code">
    <div className="ai-code-head">
      <span className="ai-code-lang">{lang || 'snippet'}</span>
      <div className="ai-code-actions">
        {onUse && (
          <button type="button" className="ai-code-btn" onClick={() => onUse(code)} title="Load into Payloads tab" aria-label="Use as payload">
            <IconTarget /><span>Use</span>
          </button>
        )}
        <CopyButton text={code} className="ai-code-btn" title="Copy code" />
      </div>
    </div>
    <pre><code>{code}</code></pre>
  </div>
);

/* Inline markdown: `code` and **bold**. Returns an array of React nodes. */
function renderInline(text, keyBase) {
  const nodes = [];
  const re = /(`[^`]+`|\*\*[^*]+\*\*)/g;
  let last = 0;
  let m;
  let i = 0;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) nodes.push(text.slice(last, m.index));
    const tok = m[0];
    if (tok[0] === '`') {
      nodes.push(<code key={`${keyBase}-c${i}`} className="ai-inline-code">{tok.slice(1, -1)}</code>);
    } else {
      nodes.push(<strong key={`${keyBase}-b${i}`}>{tok.slice(2, -2)}</strong>);
    }
    last = m.index + tok.length;
    i += 1;
  }
  if (last < text.length) nodes.push(text.slice(last));
  return nodes;
}

/* Prose block: paragraphs + bullet/numbered lists with inline formatting. */
const AiTextBlock = ({ text }) => {
  const lines = text.split('\n');
  const blocks = [];
  let list = null;
  const flushList = () => { if (list) { blocks.push(list); list = null; } };
  lines.forEach((raw) => {
    const line = raw.replace(/\s+$/, '');
    const bullet = /^\s*[-*•]\s+(.*)/.exec(line);
    const numbered = /^\s*\d+[.)]\s+(.*)/.exec(line);
    if (bullet || numbered) {
      const ordered = !!numbered;
      const item = bullet ? bullet[1] : numbered[1];
      if (!list || list.ordered !== ordered) { flushList(); list = { type: 'list', ordered, items: [] }; }
      list.items.push(item);
    } else if (line.trim() === '') {
      flushList();
    } else {
      flushList();
      blocks.push({ type: 'p', text: line });
    }
  });
  flushList();
  return (
    <>
      {blocks.map((b, i) => {
        if (b.type === 'list') {
          const Tag = b.ordered ? 'ol' : 'ul';
          return (
            <Tag key={i} className="ai-list">
              {b.items.map((it, j) => <li key={j}>{renderInline(it, `${i}-${j}`)}</li>)}
            </Tag>
          );
        }
        return <p key={i} className="ai-p">{renderInline(b.text, String(i))}</p>;
      })}
    </>
  );
};

/* Full assistant/user message content: split on fenced code, render the rest. */
function renderMessage(content, onUse) {
  const parts = [];
  const fence = /```(\w*)\n?([\s\S]*?)```/g;
  let last = 0;
  let m;
  while ((m = fence.exec(content)) !== null) {
    if (m.index > last) parts.push({ type: 'text', text: content.slice(last, m.index) });
    parts.push({ type: 'code', lang: m[1] || '', code: m[2].replace(/\n$/, '') });
    last = m.index + m[0].length;
  }
  if (last < content.length) parts.push({ type: 'text', text: content.slice(last) });
  if (parts.length === 0) parts.push({ type: 'text', text: content });
  return parts.map((p, i) => (
    p.type === 'code'
      ? <AiCodeBlock key={i} lang={p.lang} code={p.code} onUse={onUse} />
      : <AiTextBlock key={i} text={p.text} />
  ));
}

const THEME_META = {
  dark:   { icon: <IconMoon />,    label: 'Dark' },
  light:  { icon: <IconSun />,     label: 'Light' },
  system: { icon: <IconMonitor />, label: 'System' },
};

const Popup = () => {
  const toast = useToast();
  const { theme, cycle } = useTheme();
  const [elements, setElements] = useState([]);
  const [selectedIds, setSelectedIds] = useState(new Set());
  const [reflectionResults, setReflectionResults] = useState(null); // [{uniqueId, reflected, contexts}]
  const [reflectionBusy, setReflectionBusy] = useState(false);
  const [loading, setLoading] = useState(false);
  const [currentUrl, setCurrentUrl] = useState('');
  const [allowlist, setAllowlist] = useState([]);
  const [scope, setScope] = useState({ inScope: ['*'], outOfScope: [] });
  const [scopeInText, setScopeInText] = useState('*');
  const [scopeOutText, setScopeOutText] = useState('');
  const [passiveCapture, setPassiveCapture] = useState(true);
  const [inventory, setInventory] = useState({}); // { [host]: inv }
  const [headerFindings, setHeaderFindings] = useState({}); // { [host]: {url, checkedAt, findings} }
  const [findings, setFindings] = useState({}); // unified findings store { [host]: Finding[] }
  const [findingsCrossHost, setFindingsCrossHost] = useState(false); // dedup across a program's subdomains
  const [findingsMinBand, setFindingsMinBand] = useState('all'); // confidence threshold for the Findings list
  const [reportDraft, setReportDraft] = useState(null); // report-builder modal state
  const [aiReportBusy, setAiReportBusy] = useState(''); // '' | 'draft' | 'triage'
  const [escalation, setEscalation] = useState(null); // { finding, steps, rejected, depth } — AI escalation plan
  const [escalationBusy, setEscalationBusy] = useState(false);
  const [chains, setChains] = useState(null); // { chains, rejected, source } — AI-proposed exploit chains
  const [chainsBusy, setChainsBusy] = useState(false);
  const [escBudgetUsed, setEscBudgetUsed] = useState(0); // escalation steps executed this session (loop cap)
  // Phase 2: monitoring / tracker state
  const [jsScanResult, setJsScanResult] = useState(null);
  const [jsScanning, setJsScanning] = useState(false);
  const [jsWatch, setJsWatch] = useState({}); // { [host]: [{ts, diffs}] }
  const [programs, setPrograms] = useState([]);
  const [submissions, setSubmissions] = useState([]);
  const [progForm, setProgForm] = useState({ name: '', platform: 'HackerOne', url: '' });
  const [subForm, setSubForm] = useState({ programId: '', title: '', severity: 'medium', state: 'submitted', bounty: '' });
  const [notifyConfig, setNotifyConfig] = useState({ enabled: true, webhookUrl: '', webhookPlatform: 'discord' });
  const [jsMonitor, setJsMonitor] = useState({ enabled: false, intervalMinutes: 360 });
  // Phase 3: companion agent
  const [agentConfig, setAgentConfig] = useState({ url: 'http://localhost:8787', token: '' });
  const [agentHealthInfo, setAgentHealthInfo] = useState(null); // null=unknown
  const [agentTool, setAgentTool] = useState('subfinder');
  const [agentProfile, setAgentProfile] = useState('quick');
  const [agentBusy, setAgentBusy] = useState(false);
  const [agentResult, setAgentResult] = useState(null);
  const [watchList, setWatchList] = useState([]);
  const [watchInterval, setWatchInterval] = useState(360);
  const [dryRunMode, setDryRunMode] = useState(true);
  const [auditLog, setAuditLog] = useState([]);
  const [confirmAction, setConfirmAction] = useState(null);
  const [selectedVuln, setSelectedVuln] = useState(DEFAULT_VULNS[0].key);
  const [payloadSource, setPayloadSource] = useState('library'); // 'file' | 'text' | 'llm' | 'library'
  const [filePayload, setFilePayload] = useState('');
  const [fileName, setFileName] = useState('');
  const [textPayload, setTextPayload] = useState('');
  const [fileData, setFileData] = useState(null); // { base64, mime, name }
  const [llmPayload, setLlmPayload] = useState('');
  const [llmExplanation, setLlmExplanation] = useState('');
  const [llmLoading, setLlmLoading] = useState(false);
  const [aiModel, setAiModel] = useState(DEFAULT_MODEL); // selected Groq model id
  const [aiModels, setAiModels] = useState(() => decorate()); // decorated list
  const [aiReachable, setAiReachable] = useState(null); // null=checking, bool=result
  const [aiError, setAiError] = useState('');
  const [chatMessages, setChatMessages] = useState([]); // {role:'user'|'assistant', content}
  const [chatInput, setChatInput] = useState('');
  const [chatBusy, setChatBusy] = useState(false);
  const chatLogRef = useRef(null);
  const [activeTab, setActiveTab] = useState('Scan'); // 'Scan' | 'Payloads' | 'Recon' | 'History' | 'Settings'
  const [payloadHistory, setPayloadHistory] = useState([]);
  const [historyQuery, setHistoryQuery] = useState(''); // search text for History tab
  const [historyFilter, setHistoryFilter] = useState('all'); // vuln-type filter for History tab
  const [copiedHistoryIdx, setCopiedHistoryIdx] = useState(null); // index showing "copied" feedback
  const [checklistStore, setChecklistStore] = useState({}); // { [host]: { [itemId]: state } }
  const [openCategories, setOpenCategories] = useState(() => new Set([CHECKLIST[0]?.id]));
  const [recon, setRecon] = useState(null); // passive page recon snapshot
  const [reconLoading, setReconLoading] = useState(false);
  const [deepJsResult, setDeepJsResult] = useState(null); // result of deep same-origin JS scan
  const [deepJsScanning, setDeepJsScanning] = useState(false);
  const [activeReconResult, setActiveReconResult] = useState(null); // result of active recon
  const [differentialResult, setDifferentialResult] = useState(null); // result of differential/timing probe
  const [unscannable, setUnscannable] = useState(null); // { crossOriginFrames }
  const [authSession, setAuthSession] = useState(null); // Supabase session (gates the app)
  const [authReady, setAuthReady] = useState(false); // initial session check done
  // Capture extension id for origin guidance
  const extensionId = chrome?.runtime?.id || '<extension-id>'; // used in 403 guidance/help text

  useEffect(() => {
    // Load settings from storage
    chrome.storage.local.get(
      ['allowlist', 'scope', 'passiveCapture', 'inventory', 'headerFindings', 'findings', 'dryRunMode', 'auditLog', 'aiModel', 'checklistStore',
       'jsWatch', 'programs', 'submissions', 'notifyConfig', 'jsMonitor', 'agentConfig'],
      (result) => {
        setJsWatch(result.jsWatch || {});
        setHeaderFindings(result.headerFindings || {});
        setFindings(result.findings || {});
        setPrograms(result.programs || []);
        setSubmissions(result.submissions || []);
        if (result.notifyConfig) setNotifyConfig(result.notifyConfig);
        if (result.jsMonitor) setJsMonitor(result.jsMonitor);
        if (result.agentConfig) setAgentConfig(result.agentConfig);
        setAllowlist(result.allowlist || ['*']);
        // Prefer structured scope; migrate from the legacy allowlist on first run.
        const nextScope =
          result.scope && Array.isArray(result.scope.inScope)
            ? result.scope
            : scopeFromAllowlist(result.allowlist || ['*']);
        setScope(nextScope);
        setScopeInText((nextScope.inScope || []).join('\n'));
        setScopeOutText((nextScope.outOfScope || []).join('\n'));
        setPassiveCapture(result.passiveCapture !== false);
        setInventory(result.inventory || {});
        setDryRunMode(result.dryRunMode !== undefined ? result.dryRunMode : true);
        setAuditLog(result.auditLog || []);
        setPayloadHistory(result.payloadHistory || []);
        setChecklistStore(result.checklistStore || {});
        if (result.aiModel) setAiModel(result.aiModel);
      }
    );

    // Get current tab URL
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        setCurrentUrl(tabs[0].url);
      }
    });

  }, []);

  // Probe the AI proxy (models list = reachability) once the user is verified.
  useEffect(() => {
    if (!authReady || !auth.isVerified(authSession)) return;
    let cancelled = false;
    (async () => {
      setAiReachable(null);
      try {
        const ids = await ai.listModels();
        if (cancelled) return;
        setAiModels(decorate(ids));
        setAiReachable(true);
        setAiError('');
      } catch (e) {
        if (cancelled) return;
        setAiReachable(false);
        setAiError((e && e.message) || 'AI proxy unreachable');
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [authReady, authSession]);

  const onSelectModel = (id) => {
    setAiModel(id);
    try {
      chrome.storage.local.set({ aiModel: id });
    } catch (_) {}
  };

  // Auth gate: load the current session and react to sign-in/out.
  useEffect(() => {
    let subscription;
    (async () => {
      try {
        setAuthSession(await auth.getSession());
      } catch (_) {
        setAuthSession(null);
      } finally {
        setAuthReady(true);
      }
    })();
    try {
      const { data } = auth.onAuthStateChange((_event, session) => {
        setAuthSession(session);
        setAuthReady(true);
      });
      subscription = data && data.subscription;
    } catch (_) {}
    return () => {
      try {
        subscription && subscription.unsubscribe();
      } catch (_) {}
    };
  }, []);

  const refreshSession = async () => {
    try {
      setAuthSession(await auth.getSession());
    } catch (_) {}
  };

  // Single source of truth for "may I act here?" — the program scope.
  const isHostAllowed = (url) => evaluateScope(url, scope).allowed;
  const scopeStatus = (url) => evaluateScope(url, scope); // { allowed, reason, host }

  // Persist edited scope (from the two textareas) and drop the legacy allowlist.
  const saveScope = () => {
    const next = { inScope: parseScopeText(scopeInText), outOfScope: parseScopeText(scopeOutText) };
    setScope(next);
    setScopeInText(next.inScope.join('\n'));
    setScopeOutText(next.outOfScope.join('\n'));
    try { chrome.storage.local.set({ scope: next }); } catch (_) {}
    toast.success('Scope saved');
  };

  const togglePassiveCapture = () => {
    const v = !passiveCapture;
    setPassiveCapture(v);
    try { chrome.storage.local.set({ passiveCapture: v }); } catch (_) {}
  };

  const refreshInventory = () => {
    chrome.storage.local.get(['inventory', 'headerFindings', 'findings'], (r) => {
      setInventory(r.inventory || {});
      setHeaderFindings(r.headerFindings || {});
      setFindings(r.findings || {});
    });
  };

  const refreshFindings = () => {
    chrome.storage.local.get(['findings'], (r) => setFindings(r.findings || {}));
  };

  const clearFindingsForHost = (host) => {
    setFindings((prev) => {
      const next = { ...prev };
      delete next[host];
      try { chrome.storage.local.set({ findings: next }); } catch (_) {}
      return next;
    });
  };

  // Persist a batch of client-derived findings (e.g. DOM-XSS taint candidates)
  // into the unified store via the background worker, then refresh.
  const saveFindings = (list) => {
    if (!Array.isArray(list) || !list.length) return;
    try {
      chrome.runtime.sendMessage({ action: 'upsertFindings', findings: list }, () => {
        void chrome.runtime.lastError;
        refreshFindings();
      });
    } catch (_) {}
  };

  const clearHeaderFindingsForHost = (host) => {
    setHeaderFindings((prev) => {
      const next = { ...prev };
      delete next[host];
      try { chrome.storage.local.set({ headerFindings: next }); } catch (_) {}
      return next;
    });
  };

  const clearInventoryForHost = (host) => {
    setInventory((prev) => {
      const next = { ...prev };
      delete next[host];
      try { chrome.storage.local.set({ inventory: next }); } catch (_) {}
      return next;
    });
  };

  // Open the report-builder modal, prefilled from a derived finding (header /
  // DOM-XSS candidate). The human still edits and confirms before submitting.
  const draftFromFinding = (f) => {
    const v = scoreFinding(f); // gate verdict → the draft shows confidence + a low-confidence warning
    const proseToken = Date.now(); // guards the async rationale upgrade against a stale draft
    setReportDraft({
      platform: 'hackerone',
      title: f.title || 'Finding',
      target: f.host || currentHost,
      program: '',
      ref: f.ref || '',
      confidence: v.confidence,
      band: v.band,
      rationale: fallbackProse(v), // instant deterministic "why"; upgraded by the LLM below if available
      _proseToken: proseToken,
      severity: SEVERITIES.includes(f.severity) ? f.severity : 'medium',
      summary: f.type === 'dom-xss'
        ? `A DOM sink (${f.sink}) appears to be reachable from a controllable source (${(f.sources || []).join(', ')}). Needs manual confirmation.`
        : (f.evidence || ''),
      steps: '',
      impact: '',
      remediation: '',
      evidence: f.evidence || '',
      category: 'Recon',
    });
    // Best-effort LLM upgrade of the rationale — never blocks, never throws, silently
    // keeps the fallback if no provider. Only patches if this draft is still open.
    explainConfidence(f, v, { chat: ai.chat, model: aiModel }).then(({ prose, source }) => {
      if (source !== 'llm') return;
      setReportDraft((prev) => (prev && prev._proseToken === proseToken ? { ...prev, rationale: prose } : prev));
    });
  };

  // Ask the AI to propose exploit chains across the current findings, then show
  // only the ones the pure layer could ground against real findings + scope.
  const runProposeChains = async () => {
    const all = findingsCrossHost ? Object.values(findings).flat() : ((currentHost && findings[currentHost]) || []);
    const list = dedupeFindings(all, { crossHost: findingsCrossHost });
    if (!list.length) { toast.info('No findings to chain yet.'); return; }
    setChainsBusy(true);
    try {
      const res = await proposeChains(list, { model: aiModel, scope });
      if (res.source === 'error') { toast.error('Chain proposal failed — AI unavailable or returned no valid JSON.'); return; }
      if (!res.chains.length) { toast.info('No grounded chains proposed.'); return; }
      setChains(res);
    } finally {
      setChainsBusy(false);
    }
  };

  // ── AI escalation pipeline (Phase 3) ─────────────────────────────
  // Ask the AI planner for next steps to escalate a finding, then validate the
  // plan (allowlist + scope) before showing it. Nothing runs until the human
  // approves a step in the panel.
  const runEscalate = async (finding) => {
    if (!finding) return;
    const depth = Number(finding.depth) || 0;
    if (!canEscalate({ depth, budgetUsed: escBudgetUsed })) {
      toast.info('Escalation limit reached (max depth or session budget). Close and start fresh to continue.');
      return;
    }
    // Don't spend AI budget escalating pure noise; tentative+ is fair game (that's what escalation is for).
    if (!canEscalateFinding(finding, { minBand: 'tentative' })) {
      toast.info(`Skipping — this reads as noise (confidence ${scoreFinding(finding).confidence}%). Gather more signal first.`);
      return;
    }
    const host = finding.host || currentHost;
    setEscalationBusy(true);
    setEscalation({ finding, steps: [], rejected: [], depth, loading: true });
    try {
      const context = assembleContext(finding, {
        inventory: inventory[host] || (currentHost === host ? inventory[currentHost] : undefined),
        findings: findings[host] || [],
        recon,
      });
      const { steps: rawSteps } = await ai.escalateFinding(finding, context, aiModel);
      const { steps, rejected } = normalizePlan(rawSteps, { scope, host });
      setEscalation({ finding, steps, rejected, depth, loading: false });
      if (!steps.length) toast.info('No actionable escalation steps proposed.');
    } catch (e) {
      setEscalation(null);
      toast.error('Escalation failed: ' + (e?.message || 'unknown'));
    } finally {
      setEscalationBusy(false);
    }
  };

  // Resolve library payloads for a family and run them on the scanned page fields.
  const runPayloadFamily = async (family) => {
    const vuln = DEFAULT_VULNS.find((v) => v.key === family);
    if (!vuln) { toast.error('Unknown payload family: ' + family); return; }
    if (!elements.length) { toast.info('Scan the page first (Scan tab) so there are fields to test.'); return; }
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const ready = await ensureContentScript(tab);
    if (!ready) { toast.error('Content script unreachable on this page.'); return; }
    const targetIds = (selectedIds && selectedIds.size > 0) ? Array.from(selectedIds) : elements.map((e) => e.uniqueId);
    chrome.tabs.sendMessage(tab.id, { action: 'executeVulnTest', vulnKey: vuln.key, payloads: vuln.payloads, uniqueIds: targetIds }, (response) => {
      if (response && response.success) {
        const ok = response.results.filter((r) => r.success).length;
        toast.success(`${vuln.label}: applied to ${ok}/${response.results.length} field(s).`);
        addToAuditLog('VULN_TEST', { vuln: vuln.key, escalation: true, results: response.results }, 'SUCCESS');
      } else {
        toast.error('Payload run failed: ' + (response?.reason || chrome.runtime.lastError?.message || 'unknown'));
      }
    });
  };

  // Run one agent tool against a specific target (from an escalation step).
  const runAgentScanFor = (tool, target, profile) => {
    chrome.runtime.sendMessage({ action: 'agentScan', tool, target, profile: profile || 'quick' }, (response) => {
      if (chrome.runtime.lastError) { toast.error('Agent error: ' + chrome.runtime.lastError.message); return; }
      setAgentResult(response?.data || response);
      if (response && response.success === false) toast.error('Agent scan blocked: ' + (response.reason || 'unknown'));
      else toast.info(`Agent ${tool} ran against ${target}.`);
    });
  };

  // Dispatch one validated step to its existing engine handler. Counts against
  // the session budget and stamps any resulting finding one hop deeper.
  const executeStepAction = (step) => {
    setEscBudgetUsed((n) => n + 1);
    const childDepth = (Number(escalation?.depth) || 0) + 1;
    switch (step.type) {
      case 'deep_js': return runDeepJsScan();
      case 'confirm_reflection': return runConfirmReflection();
      case 'probe_endpoint': return probeEndpoint(step.target);
      case 'differential_probe': return runDifferentialProbe(step.target, step.param, childDepth);
      case 'run_payload': return runPayloadFamily(step.payloadFamily);
      case 'agent_scan': return runAgentScanFor(step.tool, step.target, step.profile);
      default: return undefined;
    }
  };

  // Run one step. Safe steps run directly; active steps go through the same
  // dry-run/confirm gate as everything else (confirmAndExecute). Blocked when
  // the session escalation budget is exhausted.
  const executeStep = (step) => {
    if (!mapStepToAction(step)) { toast.info('Manual step — follow the guidance, nothing to auto-run.'); return; }
    if (remainingBudget(escBudgetUsed) <= 0) { toast.error('Escalation action budget exhausted for this session.'); return; }
    if (isSafeStep(step)) {
      executeStepAction(step);
    } else {
      confirmAndExecute(step.type, { name: step.target || step.payloadFamily || step.tool || 'current page', type: 'escalation' }, () => executeStepAction(step));
    }
  };

  // Convenience: run only the read-only/dry-run-safe steps in one click (bounded
  // by the remaining session budget).
  const runSafeSteps = () => {
    const budget = remainingBudget(escBudgetUsed);
    if (budget <= 0) { toast.error('Escalation action budget exhausted for this session.'); return; }
    const safe = (escalation?.steps || []).filter(isSafeStep).slice(0, budget);
    if (!safe.length) { toast.info('No safe steps to run.'); return; }
    safe.forEach(executeStepAction);
    toast.info(`Running ${safe.length} safe step(s)…`);
  };

  // Open the report-builder modal, prefilled from a checklist item.
  const openReportDraft = (item, categoryName) => {
    setReportDraft({
      platform: 'hackerone',
      title: item ? item.title : 'Finding',
      target: currentHost,
      program: '',
      ref: item ? item.ref : '',
      severity: 'medium',
      summary: '',
      steps: '',
      impact: '',
      remediation: '',
      evidence: '',
      category: categoryName || '',
    });
  };

  // ── Phase 2: JS monitoring ───────────────────────────────────
  const runJsScan = () => {
    if (!isHostAllowed(currentUrl)) {
      toast.error('Current host is out of scope.');
      return;
    }
    const scripts = (currentHost && inventory[currentHost] && inventory[currentHost].scripts) || [];
    setJsScanning(true);
    chrome.runtime.sendMessage({ action: 'scanJs', pageUrl: currentUrl, scriptUrls: scripts }, (resp) => {
      setJsScanning(false);
      if (chrome.runtime.lastError) {
        toast.error('Error: ' + chrome.runtime.lastError.message);
        return;
      }
      setJsScanResult(resp);
      if (resp && resp.success && resp.dryRun) {
        toast.info(`🔒 DRY RUN: would fetch ${resp.wouldFetch.length} JS file(s). Disable Dry Run to diff.`);
      } else if (resp && resp.success) {
        toast.success(resp.interesting ? `${resp.interesting} file(s) with new surface!` : 'Scan complete — no new endpoints.');
        chrome.storage.local.get(['jsWatch'], (r) => setJsWatch(r.jsWatch || {}));
      } else {
        toast.error('JS scan blocked: ' + (resp?.reason || 'unknown'));
      }
    });
  };

  const saveNotifyConfig = (next) => {
    setNotifyConfig(next);
    try { chrome.storage.local.set({ notifyConfig: next }); } catch (_) {}
  };
  const saveJsMonitor = (next) => {
    setJsMonitor(next);
    try { chrome.storage.local.set({ jsMonitor: next }); } catch (_) {}
  };

  // ── Phase 2: program / payout tracker ────────────────────────
  const persistPrograms = (next) => {
    setPrograms(next);
    try { chrome.storage.local.set({ programs: next }); } catch (_) {}
  };
  const persistSubmissions = (next) => {
    setSubmissions(next);
    try { chrome.storage.local.set({ submissions: next }); } catch (_) {}
  };
  const addProgram = () => {
    if (!progForm.name.trim()) { toast.error('Program name required'); return; }
    persistPrograms([createProgram(progForm), ...programs]);
    setProgForm({ name: '', platform: 'HackerOne', url: '' });
  };
  const deleteProgram = (id) => {
    persistPrograms(programs.filter((p) => p.id !== id));
    persistSubmissions(submissions.filter((s) => s.programId !== id));
  };
  const addSubmission = () => {
    if (!subForm.programId) { toast.error('Pick a program first'); return; }
    if (!subForm.title.trim()) { toast.error('Finding title required'); return; }
    persistSubmissions([createSubmission(subForm), ...submissions]);
    setSubForm({ programId: subForm.programId, title: '', severity: 'medium', state: 'submitted', bounty: '' });
  };
  const setSubmissionState = (id, state) => {
    persistSubmissions(submissions.map((s) => (s.id === id ? { ...s, state } : s)));
  };
  const deleteSubmission = (id) => {
    persistSubmissions(submissions.filter((s) => s.id !== id));
  };

  // ── Phase 3: companion agent ─────────────────────────────────
  const saveAgentConfig = (next) => {
    setAgentConfig(next);
    try { chrome.storage.local.set({ agentConfig: next }); } catch (_) {}
  };
  const checkAgentHealth = () => {
    setAgentHealthInfo({ loading: true });
    chrome.runtime.sendMessage({ action: 'agentHealth' }, (resp) => {
      if (chrome.runtime.lastError || !resp || !resp.success) {
        setAgentHealthInfo({ ok: false });
        toast.error('Agent unreachable — is it running? (docker compose up)');
        return;
      }
      setAgentHealthInfo({ ok: true, ...resp.data });
      toast.success('Agent connected');
      loadWatches();
    });
  };
  const syncAgentScope = () => {
    chrome.runtime.sendMessage({ action: 'agentSyncScope' }, (resp) => {
      if (chrome.runtime.lastError || !resp || !resp.success) {
        toast.error('Scope sync failed (check URL/token)');
        return;
      }
      toast.success('Scope pushed to agent');
    });
  };
  const runAgentScan = () => {
    const target = currentHost || '';
    if (!target) { toast.error('Open an http(s) target first.'); return; }
    if (!isHostAllowed(currentUrl)) { toast.error('Target is out of scope.'); return; }
    setAgentBusy(true);
    setAgentResult(null);
    chrome.runtime.sendMessage({ action: 'agentScan', tool: agentTool, target, profile: agentProfile }, (resp) => {
      setAgentBusy(false);
      if (chrome.runtime.lastError) { toast.error('Error: ' + chrome.runtime.lastError.message); return; }
      if (!resp || !resp.success) {
        const why = (resp && (resp.reason || (resp.data && resp.data.error))) || 'failed';
        toast.error('Agent scan: ' + why);
        setAgentResult(resp || null);
        return;
      }
      setAgentResult(resp.data);
      toast.success(`${agentTool}: ${resp.data.count || 0} result(s)`);
    });
  };

  const loadWatches = () => {
    chrome.runtime.sendMessage({ action: 'agentWatches' }, (resp) => {
      if (chrome.runtime.lastError || !resp || !resp.success) { setWatchList([]); return; }
      setWatchList((resp.data && resp.data.watches) || []);
    });
  };
  const addWatch = () => {
    if (!currentHost) { toast.error('Open an http(s) target first.'); return; }
    if (!isHostAllowed(currentUrl)) { toast.error('Target is out of scope.'); return; }
    chrome.runtime.sendMessage(
      { action: 'agentCreateWatch', target: currentHost, tools: [agentTool], intervalMinutes: watchInterval, profile: agentProfile },
      (resp) => {
        if (chrome.runtime.lastError || !resp || !resp.success) {
          toast.error('Create watch failed: ' + ((resp && (resp.reason || (resp.data && resp.data.error))) || 'error'));
          return;
        }
        toast.success('Watch scheduled');
        loadWatches();
      }
    );
  };
  const runWatch = (id) => {
    chrome.runtime.sendMessage({ action: 'agentRunWatch', id }, (resp) => {
      if (chrome.runtime.lastError || !resp || !resp.success) { toast.error('Run failed'); return; }
      toast.info('Watch run queued');
      setTimeout(loadWatches, 1500);
    });
  };
  const deleteWatch = (id) => {
    chrome.runtime.sendMessage({ action: 'agentDeleteWatch', id }, () => loadWatches());
  };

  // ── Checklist (per-target methodology tracking) ──────────────
  const hostOf = (url) => {
    try { return new URL(url).hostname; } catch (_) { return ''; }
  };
  const currentHost = hostOf(currentUrl);
  // Progress map for the current host, creating a fresh one on first sight.
  const checklistProgress = (currentHost && checklistStore[currentHost]) || createChecklistProgress();

  const persistChecklist = (nextStore) => {
    setChecklistStore(nextStore);
    try { chrome.storage.local.set({ checklistStore: nextStore }); } catch (_) {}
  };

  const setChecklistItemState = (itemId, state) => {
    if (!currentHost) {
      toast.error('Open a normal http(s) page to track a checklist for it.');
      return;
    }
    const progress = { ...checklistProgress, [itemId]: state };
    persistChecklist({ ...checklistStore, [currentHost]: progress });
  };

  const resetChecklist = () => {
    if (!currentHost) return;
    persistChecklist({ ...checklistStore, [currentHost]: createChecklistProgress() });
  };

  const toggleCategory = (id) => {
    setOpenCategories((prev) => {
      const copy = new Set(prev);
      if (copy.has(id)) copy.delete(id); else copy.add(id);
      return copy;
    });
  };

  // Jump from a checklist item to its preset payloads on the Scan tab.
  const jumpToPayload = (payloadKey) => {
    if (DEFAULT_VULNS.some((v) => v.key === payloadKey)) setSelectedVuln(payloadKey);
    setPayloadSource('library');
    setActiveTab('Scan');
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
      toast.error('Current host is not in allowlist! Add it in settings first.');
      return;
    }

    setLoading(true);
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      // Ensure the content script is present (inject it if the page predates the
      // extension load) before messaging.
      const ready = await ensureContentScript(tab);
      if (!ready) {
        toast.error('Content script could not be reached on this page. Open a normal http(s) page and try again.');
        setLoading(false);
        return;
      }

      chrome.tabs.sendMessage(tab.id, { action: 'scanPage' }, (response) => {
        if (chrome.runtime.lastError) {
          console.error('Error:', chrome.runtime.lastError);
          toast.error('Please refresh the page and try again.');
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
      toast.error('Current host is not in allowlist! Add it in settings first.');
      return;
    }
    setReconLoading(true);
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      const ready = await ensureContentScript(tab);
      if (!ready) {
        toast.error('Content script could not be reached on this page. Open a normal http(s) page and try again.');
        setReconLoading(false);
        return;
      }
      chrome.tabs.sendMessage(tab.id, { action: 'getPageRecon' }, (response) => {
        const lastErr = chrome.runtime.lastError && chrome.runtime.lastError.message;
        if (response && response.success) {
          setRecon(response.recon);
          saveFindings(taintFindings(response.recon.sinks, currentHost));
          addToAuditLog('PASSIVE_RECON', { endpoints: response.recon.endpoints?.length || 0 }, 'SUCCESS');
        } else {
          toast.error('Recon failed: ' + (response?.message || lastErr || 'unknown error'));
        }
        setReconLoading(false);
      });
    } catch (e) {
      console.error('Recon error', e);
      setReconLoading(false);
    }
  };

  // Deep JS scan: fetch same-origin external scripts and mine them for
  // endpoints, secrets and DOM-XSS sinks. Same-origin GET only, scope-gated in
  // the content script; results fold into the per-host inventory.
  const runDeepJsScan = async () => {
    if (!isHostAllowed(currentUrl)) {
      toast.error('Current host is not in allowlist! Add it in settings first.');
      return;
    }
    setDeepJsScanning(true);
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      const ready = await ensureContentScript(tab);
      if (!ready) {
        toast.error('Content script could not be reached on this page. Open a normal http(s) page and try again.');
        setDeepJsScanning(false);
        return;
      }
      chrome.tabs.sendMessage(tab.id, { action: 'deepJsScan' }, (response) => {
        const lastErr = chrome.runtime.lastError && chrome.runtime.lastError.message;
        if (response && response.success) {
          setDeepJsResult(response);
          addToAuditLog('DEEP_JS_SCAN', {
            scripts: response.scanned,
            endpoints: response.endpoints?.length || 0,
            secrets: response.secrets?.length || 0,
            sinks: response.sinks?.length || 0,
          }, 'SUCCESS');
          saveFindings(taintFindings(response.sinks, currentHost));
          refreshInventory();
          toast.success(`Deep JS scan: ${response.scanned} script(s) · ${response.secrets?.length || 0} secret(s) · ${response.sinks?.length || 0} sink(s).`);
        } else {
          toast.error('Deep JS scan failed: ' + (response?.reason || lastErr || 'unknown error'));
        }
        setDeepJsScanning(false);
      });
    } catch (e) {
      console.error('Deep JS scan error', e);
      setDeepJsScanning(false);
    }
  };

  // Light active recon (background worker). Honors allowlist + dry-run + rate-limit.
  const runActiveRecon = (includeDiscovered = false) => {
    const endpoints = (recon && recon.endpoints) || [];
    chrome.runtime.sendMessage(
      { action: 'activeRecon', pageUrl: currentUrl, endpoints, includeDiscovered },
      (response) => {
        if (chrome.runtime.lastError) {
          toast.error('Error: ' + chrome.runtime.lastError.message);
          return;
        }
        setActiveReconResult(response);
        if (response && response.success && response.dryRun) {
          toast.info(`🔒 DRY RUN: would fetch ${response.wouldFetch.length} URL(s). Disable Dry Run to execute.`);
        } else if (response && !response.success) {
          toast.error('Active recon blocked: ' + (response.reason || 'unknown'));
        }
      }
    );
  };

  const probeEndpoint = (endpoint) => {
    chrome.runtime.sendMessage(
      { action: 'probeEndpoint', pageUrl: currentUrl, endpoint },
      (response) => {
        if (chrome.runtime.lastError) {
          toast.error('Error: ' + chrome.runtime.lastError.message);
          return;
        }
        if (response && response.success && response.dryRun) {
          toast.info(`🔒 DRY RUN: would GET ${(response.wouldFetch || []).join(', ')}`);
        } else if (response && response.success) {
          const r = response.result || {};
          toast.info(`Probed ${r.url} — Status: ${r.status} ${r.ok ? '✅' : ''}`);
        } else {
          toast.error('Probe blocked: ' + (response?.reason || 'unknown'));
        }
      }
    );
  };

  // Differential/timing oracle probe on one endpoint param (background worker).
  // GET-only, scope-gated, dry-run aware, rate-limited.
  const runDifferentialProbe = (endpoint, param, escalationDepth) => {
    chrome.runtime.sendMessage(
      { action: 'differentialProbe', pageUrl: currentUrl, url: endpoint, param, escalationDepth },
      (response) => {
        if (chrome.runtime.lastError) {
          toast.error('Error: ' + chrome.runtime.lastError.message);
          return;
        }
        setDifferentialResult(response);
        if (response && response.success && response.dryRun) {
          toast.info(`🔒 DRY RUN: would GET ${response.wouldFetch.length} variant(s) on "${response.param}". Disable Dry Run to probe.`);
        } else if (response && response.success) {
          if (response.finding) {
            toast.success(`⚠️ ${response.finding.title} · conf ${response.finding.confidence}`);
          } else {
            toast.info(`No differential signal on "${response.param}".`);
          }
        } else {
          toast.error('Differential probe blocked: ' + (response?.reason || 'unknown'));
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
        toast.error('Content script could not be reached on this page. Open a normal http(s) page and try again.');
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
          toast.error('Could not capture page source');
        }
      });
    } catch (e) {
      toast.error('Export failed: ' + e.message);
    }
  };

  const confirmAndExecute = (action, element, callback) => {
    if (dryRunMode) {
      toast.info(`🔒 DRY RUN MODE: Would execute ${action} on ${element.name || element.type}`);
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
      toast.error('Failed to read file');
    }
  };

  const fetchLlmSuggestion = async () => {
    const vuln = DEFAULT_VULNS.find(v => v.key === selectedVuln);
    setLlmLoading(true);
    try {
      const suggestion = await ai.generatePayload({
        elementType: 'input',
        elementName: '*',
        testType: 'Payload Generation',
        vulnerability: vuln?.label || selectedVuln,
      }, aiModel);
      setLlmPayload(suggestion.payload || '');
      setLlmExplanation(suggestion.explanation || '');
      setPayloadSource('llm');
      setAiReachable(true);
      toast.success('Payload generated');
    } catch (e) {
      const msg = (e && e.message) || 'AI generation failed.';
      toast.error(msg);
      setAiError(msg);
    } finally {
      setLlmLoading(false);
    }
  };

  // Keep the chat pinned to the newest message as it grows / while thinking.
  useEffect(() => {
    const el = chatLogRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [chatMessages, chatBusy]);

  // Route a code snippet from the AI reply straight into the Payloads tab.
  const useCodeAsPayload = (code) => {
    const clean = (code || '').trim();
    if (!clean) return;
    setPayloadSource('text');
    setTextPayload(clean);
    setActiveTab('Payloads');
    toast.success('Loaded into Payloads');
  };

  const sendChat = async (text) => {
    const content = (text != null ? text : chatInput).trim();
    if (!content || chatBusy) return;
    const next = [...chatMessages, { role: 'user', content }];
    setChatMessages(next);
    setChatInput('');
    setChatBusy(true);
    try {
      const reply = await ai.chat(next, aiModel);
      setChatMessages([...next, { role: 'assistant', content: reply }]);
      setAiReachable(true);
    } catch (e) {
      const msg = (e && e.message) || 'AI chat failed.';
      toast.error(msg);
      setChatMessages([...next, { role: 'assistant', content: `⚠️ ${msg}` }]);
    } finally {
      setChatBusy(false);
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
        toast.error('Content script could not be reached on this page. Open a normal http(s) page and try again.');
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
              toast.success(`File attached to ${successCount}/${response.results.length} fields`);
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
              toast.error('Failed to attach file');
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
              toast.success(`${vuln.label} test applied to ${successCount}/${response.results.length} fields`);
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
              toast.error('Failed to execute test');
              addToAuditLog('VULN_TEST', { vuln: vuln.key }, 'FAILED');
            }
          }
        );
      }
    };

    confirmAndExecute(`${vuln.label} Test`, { name: vuln.key, type: 'vuln' }, executeAction);
  };

  // Confirm reflection: inject a unique benign marker into the selected fields,
  // re-read the DOM, and report WHERE it reflected. DOM-only, reversible, no
  // network — so it runs directly (scope-gated in the content script).
  const runConfirmReflection = async () => {
    if (!isHostAllowed(currentUrl)) {
      toast.error('Current host is out of scope.');
      return;
    }
    setReflectionBusy(true);
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      const ready = await ensureContentScript(tab);
      if (!ready) {
        toast.error('Content script could not be reached on this page. Open a normal http(s) page and try again.');
        setReflectionBusy(false);
        return;
      }
      const targetIds = (selectedIds && selectedIds.size > 0)
        ? Array.from(selectedIds)
        : elements.map((e) => e.uniqueId);
      chrome.tabs.sendMessage(tab.id, { action: 'confirmReflection', uniqueIds: targetIds }, (response) => {
        const lastErr = chrome.runtime.lastError && chrome.runtime.lastError.message;
        if (response && response.success) {
          setReflectionResults(response.results);
          const hits = response.results.filter((r) => r.reflected);
          addToAuditLog('CONFIRM_REFLECTION', {
            tested: response.results.length,
            reflected: hits.length,
            contexts: Array.from(new Set(hits.flatMap((r) => r.contexts || []))),
          }, 'SUCCESS');
          if (hits.length) toast.success(`Reflected in ${hits.length}/${response.results.length} field(s).`);
          else toast.info('No reflection detected in the DOM.');
        } else {
          toast.error('Reflection check failed: ' + (response?.reason || lastErr || 'unknown'));
        }
        setReflectionBusy(false);
      });
    } catch (e) {
      console.error('Reflection check error', e);
      setReflectionBusy(false);
    }
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

  // Classify a scanned field by attack-surface signal so cards can flag the
  // high-value targets. Derived from the extraction tags (no new data needed).
  const SCAN_HIGH_TAGS = ['file-upload', 'password', 'unvalidated'];
  const SCAN_FLAG_TAGS = ['hidden', 'csrf-token', 'redirect-param', 'id-param'];
  const scanRiskOf = (el) => {
    const tags = (el && el.tags) || [];
    if (tags.some((t) => SCAN_HIGH_TAGS.includes(t))) return 'high';
    if (tags.some((t) => SCAN_FLAG_TAGS.includes(t))) return 'flag';
    return null;
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

  const copyHistoryEntry = async (entry, idx) => {
    if (!entry || !entry.payloads) return;
    const text = entry.payloads.join('\n');
    try {
      await navigator.clipboard.writeText(text);
      setCopiedHistoryIdx(idx);
      setTimeout(() => setCopiedHistoryIdx((cur) => (cur === idx ? null : cur)), 1500);
    } catch (e) { toast.error('Copy failed'); }
  };

  const deleteHistoryEntry = (index) => {
    setPayloadHistory(prev => {
      const copy = [...prev];
      copy.splice(index, 1);
      try { chrome.storage.local.set({ payloadHistory: copy }); } catch (e) { /* ignore */ }
      return copy;
    });
  };

  const clearPayloadHistory = () => {
    if (!payloadHistory.length) return;
    const count = payloadHistory.length;
    setConfirmAction({
      message: `Clear all ${count} saved history ${count === 1 ? 'entry' : 'entries'}? This cannot be undone.`,
      onConfirm: () => {
        setPayloadHistory([]);
        try { chrome.storage.local.set({ payloadHistory: [] }); } catch (e) { /* ignore */ }
        toast.success('History cleared');
      },
    });
  };

  // Human-readable relative time ("just now", "5m ago", "3h ago", "2d ago")
  const formatRelativeTime = (ts) => {
    const then = new Date(ts).getTime();
    if (Number.isNaN(then)) return '';
    const diff = Math.max(0, Date.now() - then);
    const min = Math.floor(diff / 60000);
    if (min < 1) return 'just now';
    if (min < 60) return `${min}m ago`;
    const hr = Math.floor(min / 60);
    if (hr < 24) return `${hr}h ago`;
    const day = Math.floor(hr / 24);
    if (day < 7) return `${day}d ago`;
    return new Date(ts).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  };

  // Friendly label for a saved vuln key (falls back to the raw key / "Custom")
  const vulnLabel = (key) => {
    if (!key) return 'Custom';
    const match = DEFAULT_VULNS.find((v) => v.key === key);
    return match ? match.label : key;
  };

  const IconIris = () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" />
      <line x1="14.31" y1="8" x2="20.05" y2="17.94" />
      <line x1="9.69" y1="8" x2="21.17" y2="8" />
      <line x1="7.38" y1="12" x2="13.12" y2="2.06" />
      <line x1="9.69" y1="16" x2="3.95" y2="6.06" />
      <line x1="14.31" y1="16" x2="2.83" y2="16" />
      <line x1="16.62" y1="12" x2="10.88" y2="21.94" />
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
  const IconChecklist = () => (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>
    </svg>
  );
  const IconPrograms = () => (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="12" y1="1" x2="12" y2="23"/><path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/>
    </svg>
  );
  const IconConfig = () => (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="4" y1="6" x2="20" y2="6"/><line x1="4" y1="12" x2="20" y2="12"/><line x1="4" y1="18" x2="20" y2="18"/>
      <circle cx="8" cy="6" r="2" fill="currentColor" stroke="none"/><circle cx="16" cy="12" r="2" fill="currentColor" stroke="none"/><circle cx="10" cy="18" r="2" fill="currentColor" stroke="none"/>
    </svg>
  );
  const IconRadar = () => (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M19.07 4.93A10 10 0 1 0 22 12"/><path d="M13.5 6.5a6 6 0 1 0 4 4"/><path d="M9.5 9.5a2 2 0 1 0 2.5 2.5"/><path d="M12 12 22 2"/>
    </svg>
  );
  const IconBolt = () => (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M13 2 3 14h7l-1 8 10-12h-7l1-8z"/>
    </svg>
  );
  const IconChevron = () => (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <path d="m6 9 6 6 6-6"/>
    </svg>
  );
  /* ── Config section icons ── */
  const IconShield = () => (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>
    </svg>
  );
  const IconEye = () => (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/>
    </svg>
  );
  const IconBell = () => (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/>
    </svg>
  );
  const IconRefresh = () => (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M23 4v6h-6"/><path d="M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
    </svg>
  );
  const IconServer = () => (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/>
      <line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/>
    </svg>
  );
  const IconScroll = () => (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>
      <line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="14" y2="17"/>
    </svg>
  );
  const IconSparkle = () => (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 3v4M12 17v4M3 12h4M17 12h4"/><path d="M12 8l1.5 2.5L16 12l-2.5 1.5L12 16l-1.5-2.5L8 12l2.5-1.5z"/>
    </svg>
  );
  /* ── Programs tab icons ── */
  const IconDollar = () => (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="12" y1="1" x2="12" y2="23"/><path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/>
    </svg>
  );
  const IconCheckCircle = () => (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
    </svg>
  );
  const IconExternalLink = () => (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>
    </svg>
  );
  const IconTrophy = () => (
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M6 9H4.5a2.5 2.5 0 0 1 0-5H6"/><path d="M18 9h1.5a2.5 2.5 0 0 0 0-5H18"/>
      <path d="M4 22h16"/><path d="M10 14.66V17c0 .55-.47.98-.97 1.21C7.85 18.75 7 20.24 7 22"/>
      <path d="M14 14.66V17c0 .55.47.98.97 1.21C16.15 18.75 17 20.24 17 22"/><path d="M18 2H6v7a6 6 0 0 0 12 0V2z"/>
    </svg>
  );
  const IconPlus = () => (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
    </svg>
  );

  const ThemeToggleButton = (
    <button
      className="theme-toggle"
      onClick={cycle}
      title={`Theme: ${THEME_META[theme].label} (click to change)`}
      aria-label={`Theme: ${THEME_META[theme].label}`}
    >
      {THEME_META[theme].icon}
    </button>
  );

  // ── Auth gate ──────────────────────────────────────────────
  const verified = auth.isVerified(authSession);

  if (!authReady) {
    return (
      <div className="sectest-container">
        <div className="auth-loading">Loading…</div>
      </div>
    );
  }

  if (!verified) {
    return (
      <div className="sectest-container">
        <div className="header">
          <h2>
            <span className="header-icon"><IconIris /></span>
            Iris
          </h2>
          <div className="header-actions">{ThemeToggleButton}</div>
        </div>
        <Login onAuthed={refreshSession} />
      </div>
    );
  }

  return (
    <div className="sectest-container">
      <div className="header">
        <h2>
          <span className="header-icon"><IconIris /></span>
          Iris
        </h2>
        <div className="header-actions">
          <span
            className={`ai-dot ai-dot-${aiReachable === null ? 'checking' : aiReachable ? 'ok' : 'down'}`}
            title={aiReachable === null ? 'Checking AI proxy…' : aiReachable ? 'AI proxy connected' : 'AI proxy unreachable'}
          />
          {ThemeToggleButton}
          <div className={`status-badge${dryRunMode ? '' : ' live'}`}>
            {dryRunMode ? 'Dry Run' : 'Live'}
          </div>
          <AccountMenu
            email={authSession?.user?.email}
            onSignedOut={() => setAuthSession(null)}
          />
        </div>
      </div>

      {!isHostAllowed(currentUrl) && (
        <div className="warning-banner">
          {currentHost ? <>Out of scope: <code>{currentHost}</code> — add it in Config</> : 'Open an http(s) target'}
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
        <button className={"tab" + (activeTab === 'Findings' ? ' active' : '')} onClick={() => setActiveTab('Findings')} aria-label="Findings">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M4 22V4a1 1 0 0 1 1-1h11l-2 4 2 4H5"/><line x1="4" y1="22" x2="4" y2="15"/></svg>
          Findings
        </button>
        <button className={"tab" + (activeTab === 'Checklist' ? ' active' : '')} onClick={() => setActiveTab('Checklist')} aria-label="Checklist">
          <IconChecklist />Checklist
        </button>
        <button className={"tab" + (activeTab === 'Programs' ? ' active' : '')} onClick={() => setActiveTab('Programs')} aria-label="Programs">
          <IconPrograms />Programs
        </button>
        <button className={"tab" + (activeTab === 'AI' ? ' active' : '')} onClick={() => setActiveTab('AI')} aria-label="AI">
          <IconAI />AI
        </button>
        <button className={"tab" + (activeTab === 'History' ? ' active' : '')} onClick={() => setActiveTab('History')} aria-label="History">
          <IconHistory />History
        </button>
        <button className={"tab" + (activeTab === 'Settings' ? ' active' : '')} onClick={() => setActiveTab('Settings')} aria-label="Config">
          <IconConfig />Config
        </button>
      </div>

      {activeTab === 'Scan' && (() => {
        const allowed = isHostAllowed(currentUrl);
        const selCount = (selectedIds && selectedIds.size) || 0;
        const highCount = elements.filter((e) => scanRiskOf(e) === 'high').length;
        const flagCount = elements.filter((e) => scanRiskOf(e) === 'flag').length;
        const vuln = DEFAULT_VULNS.find((v) => v.key === selectedVuln);
        const presetCount = vuln && vuln.payloads ? vuln.payloads.length : 0;
        return (
        <div className="scan-tab">
          {/* Primary action */}
          <div className="scan-hero">
            <button onClick={scanPage} disabled={loading} className="scan-run" aria-label={loading ? 'Scanning' : 'Scan page'}>
              {loading ? <span className="scan-spin" aria-hidden="true" /> : <IconRadar />}
              <span>{loading ? 'Scanning…' : elements.length ? 'Rescan page' : 'Scan page'}</span>
            </button>
            <button onClick={() => setActiveTab('Settings')} className="scan-config" title="Scope & settings">
              <IconConfig /><span>Config</span>
            </button>
          </div>

          {/* Attack runner */}
          <div className="scan-runner">
            <div className="scan-runner-top">
              <span className="scan-runner-title"><IconBolt />Attack runner</span>
              <span className={`scan-runner-scope${selCount ? ' targeted' : ''}`}>
                {selCount > 0 ? `${selCount} field${selCount === 1 ? '' : 's'} targeted` : 'targets every field'}
              </span>
            </div>
            <div className="scan-runner-row">
              <div className="scan-select">
                <select value={selectedVuln} onChange={(e) => setSelectedVuln(e.target.value)} aria-label="Attack type">
                  {DEFAULT_VULNS.map((v) => (
                    <option key={v.key} value={v.key}>{v.label}</option>
                  ))}
                </select>
                <span className="scan-select-caret" aria-hidden="true"><IconChevron /></span>
              </div>
              <button onClick={runVulnTest} className="btn-secondary" disabled={!allowed} title={allowed ? 'Inject the selected preset payloads' : 'Target is out of scope'}>
                Run test
              </button>
              <button onClick={runConfirmReflection} className="btn-secondary" disabled={reflectionBusy || !allowed} title="Inject a benign marker and report where it reflects (DOM-only, reversible)">
                {reflectionBusy ? 'Checking…' : 'Confirm reflection'}
              </button>
            </div>
            <p className="scan-runner-hint">
              {presetCount} preset payload{presetCount === 1 ? '' : 's'} · runs on selected fields, or every field if none are selected.
            </p>
          </div>

          {reflectionResults && (
            <div className="reflection-results">
              <div className="checklist-sub" style={{ marginBottom: 6 }}>
                Reflection check — a marker in <code>js</code> or <code>attribute</code> context is a strong XSS signal (confirm manually).
              </div>
              {reflectionResults.map((r, i) => {
                const el = elements.find((e) => e.uniqueId === r.uniqueId);
                const name = el ? (el.name || el.id || el.uniqueId) : r.uniqueId;
                if (!r.success) return <div key={i} className="muted" style={{ fontSize: 11 }}>{name}: {r.reason}</div>;
                return (
                  <div key={i} className={`agent-finding ${r.reflected ? 'sev-high' : ''}`} style={{ fontSize: 12 }}>
                    {r.reflected
                      ? <><span className="sev-badge">reflected</span> <strong>{name}</strong> → {r.contexts.map((c) => <span key={c} className="tag tag-fw">{c}</span>)}</>
                      : <><strong>{name}</strong> <span className="muted">— not reflected</span></>}
                  </div>
                );
              })}
            </div>
          )}

          {/* Results */}
          <div className="elements-list">
            {loading ? (
              <div className="scan-fields" aria-hidden="true">
                {[0, 1, 2, 3].map((i) => (
                  <div key={i} className="scan-skeleton">
                    <div className="scan-skeleton-head" />
                    <div className="scan-skeleton-line" />
                  </div>
                ))}
              </div>
            ) : elements.length === 0 ? (
              <div className="scan-empty">
                <span className="scan-empty-icon"><IconRadar /></span>
                <p className="scan-empty-title">No fields discovered yet</p>
                <p className="scan-empty-sub">
                  {allowed
                    ? 'Scan the page to map every input, form and upload — then target them with payloads.'
                    : 'This target is out of scope. Add its host in Config before scanning.'}
                </p>
                {allowed
                  ? <button onClick={scanPage} className="scan-empty-cta" disabled={loading}>Scan this page</button>
                  : <button onClick={() => setActiveTab('Settings')} className="scan-empty-cta">Open Config</button>}
              </div>
            ) : (
              <>
                <div className="scan-summary">
                  <div className="scan-summary-count">
                    <b>{elements.length}</b> field{elements.length === 1 ? '' : 's'}
                    {(highCount > 0 || flagCount > 0) && (
                      <span className="scan-summary-chips">
                        {highCount > 0 && <span className="scan-chip danger">{highCount} high-signal</span>}
                        {flagCount > 0 && <span className="scan-chip warn">{flagCount} flagged</span>}
                        {selCount > 0 && <span className="scan-chip accent">{selCount} selected</span>}
                      </span>
                    )}
                    {highCount === 0 && flagCount === 0 && selCount > 0 && (
                      <span className="scan-summary-chips"><span className="scan-chip accent">{selCount} selected</span></span>
                    )}
                  </div>
                  <div className="scan-summary-actions">
                    <button className="scan-mini" onClick={selectAll} title="Select all fields">All</button>
                    <button className="scan-mini" onClick={selectFilesOnly} title="Select file-upload fields">Files</button>
                    <button className="scan-mini" onClick={clearSelection} disabled={selCount === 0} title="Clear selection">Clear</button>
                  </div>
                </div>

                <div className="scan-fields">
                  {elements.map((element, idx) => {
                    const risk = scanRiskOf(element);
                    const sel = !!(selectedIds && selectedIds.has && selectedIds.has(element.uniqueId));
                    return (
                      <div key={idx} className={`element-card${sel ? ' selected' : ''}${risk ? ' risk-' + risk : ''}`}>
                        <label className="element-header">
                          <input
                            type="checkbox"
                            checked={sel}
                            onChange={() => toggleSelection(element.uniqueId)}
                            title="Select this field for payloads/attachments"
                          />
                          <span className="element-icon">{getElementIcon(element.type)}</span>
                          <span className="element-type">{element.type}</span>
                          <span className="element-name">{element.name || 'unnamed'}</span>
                          {risk === 'high' && <span className="risk-badge">high-signal</span>}
                        </label>

                        {element.tags && element.tags.length > 0 && (
                          <div className="tag-row">
                            {element.tags.map((t) => (
                              <span key={t} className={'tag tag-' + t}>{t}</span>
                            ))}
                          </div>
                        )}

                        <div className="element-details">
                          {element.subType && <div><span className="ed-k">Type</span> {element.subType}</div>}
                          {element.id && <div><span className="ed-k">ID</span> {element.id}</div>}
                          {element.context && element.context !== 'light' && <div><span className="ed-k">Context</span> {element.context}</div>}
                          {element.formMethod && <div><span className="ed-k">Form</span> {element.formMethod.toUpperCase()} {element.formAction || '(self)'}</div>}
                          {element.placeholder && <div><span className="ed-k">Placeholder</span> {element.placeholder}</div>}
                          {element.maxlength != null && <div><span className="ed-k">Maxlength</span> {element.maxlength}</div>}
                          {element.pattern && <div><span className="ed-k">Pattern</span> <code>{element.pattern}</code></div>}
                          {element.required && <div className="badge-required">Required</div>}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </>
            )}
          </div>
          {unscannable && unscannable.crossOriginFrames > 0 && (
            <div className="hint scan-oob-hint">
              {unscannable.crossOriginFrames} cross-origin frame(s) could not be scanned.
            </div>
          )}
        </div>
        );
      })()}

      {activeTab === 'Payloads' && (() => {
        const vuln = DEFAULT_VULNS.find((v) => v.key === selectedVuln);
        const presetPayloads = (vuln && vuln.payloads) || [];
        const textLines = textPayload.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
        const SOURCES = [
          { key: 'library', icon: <IconLayers />, title: 'Preset library', desc: 'Curated payloads for the selected attack' },
          { key: 'file', icon: <IconUpload />, title: 'Custom file', desc: 'Upload any file to inject or attach' },
          { key: 'text', icon: <IconPencil />, title: 'Type your own', desc: 'Write payloads, one per line' },
          { key: 'llm', icon: <IconWand />, title: 'AI suggestion', desc: 'Generate one with Iris AI' },
        ];
        const activeCount =
          payloadSource === 'library' ? presetPayloads.length
          : payloadSource === 'text' ? textLines.length
          : payloadSource === 'file' ? (fileData ? 1 : 0)
          : payloadSource === 'llm' ? (llmPayload.trim() ? 1 : 0)
          : 0;
        const activeSource = SOURCES.find((s) => s.key === payloadSource);
        return (
        <div className="pl-tab">
          <div className="pl-head">
            <h3>Payload source</h3>
            <p>Pick what the Scan tab’s <b>Run test</b> injects into your selected fields.</p>
          </div>

          <div className="pl-sources" role="radiogroup" aria-label="Payload source">
            {SOURCES.map((s) => (
              <label key={s.key} className={`pl-card${payloadSource === s.key ? ' active' : ''}`}>
                <input
                  type="radio"
                  name="payloadSource"
                  value={s.key}
                  checked={payloadSource === s.key}
                  onChange={(e) => setPayloadSource(e.target.value)}
                />
                <span className="pl-card-icon">{s.icon}</span>
                <span className="pl-card-text">
                  <span className="pl-card-title">{s.title}</span>
                  <span className="pl-card-desc">{s.desc}</span>
                </span>
                <span className="pl-card-check" aria-hidden="true"><IconCheck /></span>
              </label>
            ))}
          </div>

          <div className="pl-detail">
            {payloadSource === 'library' && (
              <div className="pl-panel">
                <div className="pl-panel-row">
                  <label className="pl-field-label" htmlFor="pl-vuln">Attack class</label>
                  <div className="scan-select">
                    <select id="pl-vuln" value={selectedVuln} onChange={(e) => setSelectedVuln(e.target.value)}>
                      {DEFAULT_VULNS.map((v) => (
                        <option key={v.key} value={v.key}>{v.label}</option>
                      ))}
                    </select>
                    <span className="scan-select-caret" aria-hidden="true"><IconChevron /></span>
                  </div>
                </div>
                <div className="pl-preset-head">
                  <span>{presetPayloads.length} preset payload{presetPayloads.length === 1 ? '' : 's'}</span>
                  {presetPayloads.length > 0 && <CopyButton text={presetPayloads.join('\n')} className="ai-icon-btn" title="Copy all" />}
                </div>
                <ul className="pl-preset-list">
                  {presetPayloads.map((p, i) => (
                    <li key={i}><code>{p}</code></li>
                  ))}
                </ul>
              </div>
            )}

            {payloadSource === 'file' && (
              <div className="pl-panel">
                <label className="pl-dropzone">
                  <input type="file" accept="*/*" onChange={onFileChange} />
                  <span className="pl-dropzone-icon"><IconUpload /></span>
                  <span className="pl-dropzone-title">{fileData ? 'Replace file' : 'Choose a file'}</span>
                  <span className="pl-dropzone-sub">Any type · injected as text or attached to file inputs</span>
                </label>
                {fileData && (
                  <div className="pl-file">
                    <span className="pl-file-icon"><IconFile /></span>
                    <span className="pl-file-meta">
                      <span className="pl-file-name">{fileData.name || fileName}</span>
                      <span className="pl-file-sub">{fileData.mime || 'unknown type'}</span>
                    </span>
                  </div>
                )}
              </div>
            )}

            {payloadSource === 'text' && (
              <div className="pl-panel">
                <div className="pl-panel-row">
                  <label className="pl-field-label" htmlFor="pl-text">Payloads</label>
                  <span className="pl-count">{textLines.length} line{textLines.length === 1 ? '' : 's'}</span>
                </div>
                <textarea
                  id="pl-text"
                  className="pl-textarea"
                  rows={6}
                  placeholder={"<script>alert(1)</script>\n' OR '1'='1"}
                  value={textPayload}
                  onChange={(e) => setTextPayload(e.target.value)}
                />
                <p className="pl-note">One payload per line · blank lines are ignored.</p>
              </div>
            )}

            {payloadSource === 'llm' && (
              <div className="pl-panel">
                <button className="pl-generate" onClick={fetchLlmSuggestion} disabled={llmLoading}>
                  {llmLoading
                    ? <><span className="scan-spin" aria-hidden="true" />Generating…</>
                    : <><IconWand />Generate for {vuln ? vuln.label : 'attack'}</>}
                </button>
                {llmPayload ? (
                  <div className="pl-ai-out">
                    <div className="pl-ai-out-head">
                      <span>Suggested payload</span>
                      <CopyButton text={llmPayload} className="ai-icon-btn" title="Copy" />
                    </div>
                    <pre className="pl-ai-code"><code>{llmPayload}</code></pre>
                  </div>
                ) : (
                  !llmLoading && <p className="pl-note">Iris crafts a payload for the selected attack class using your chosen model.</p>
                )}
                {llmExplanation && <div className="pl-ai-why"><b>Why</b> {llmExplanation}</div>}
                {aiReachable === false && (
                  <div className="llm-error">
                    AI proxy not reachable — check the Edge Function &amp; login.
                    {aiError && <div className="pl-ai-error-detail">{aiError}</div>}
                  </div>
                )}
              </div>
            )}
          </div>

          <div className="pl-summary">
            <span className={`pl-summary-dot${activeCount > 0 ? ' ready' : ''}`} />
            <span>Active source: <b>{activeSource ? activeSource.title : '—'}</b></span>
            <span className="pl-summary-count">{activeCount > 0 ? `${activeCount} payload${activeCount === 1 ? '' : 's'} ready` : 'nothing ready yet'}</span>
          </div>
        </div>
        );
      })()}

      {activeTab === 'Recon' && (
        <div className="recon-panel">
          {(() => {
            const inv = (currentHost && inventory[currentHost]) || emptyInventory();
            const sum = summarizeInventory(inv);
            const sumHead = (label, n, tone) => (
              <summary className={`inv-sum${tone ? ' tone-' + tone : ''}`}>
                <span className="inv-caret" aria-hidden="true"><IconChevron /></span>
                <span className="inv-sum-label">{label}</span>
                <span className="inv-count">{n}</span>
              </summary>
            );
            const STAT_ICONS = {
              pages: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg>,
              endpoints: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>,
              params: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="4" y1="9" x2="20" y2="9"/><line x1="4" y1="15" x2="20" y2="15"/><line x1="10" y1="3" x2="8" y2="21"/><line x1="16" y1="3" x2="14" y2="21"/></svg>,
              scripts: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>,
              forms: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="4" width="18" height="16" rx="2"/><line x1="7" y1="9" x2="17" y2="9"/><line x1="7" y1="13" x2="13" y2="13"/></svg>,
              cookies: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 2a10 10 0 1 0 10 10 4 4 0 0 1-5-5 4 4 0 0 1-5-5z"/><circle cx="8.5" cy="12.5" r="1" fill="currentColor" stroke="none"/><circle cx="14" cy="15" r="1" fill="currentColor" stroke="none"/><circle cx="15" cy="9" r="1" fill="currentColor" stroke="none"/></svg>,
              secrets: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>,
              sinks: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>,
            };
            const STATS = [
              { key: 'pages', label: 'Pages', value: sum.pages },
              { key: 'endpoints', label: 'Endpoints', value: sum.endpoints },
              { key: 'params', label: 'Params', value: sum.params },
              { key: 'scripts', label: 'Scripts', value: sum.scripts },
              { key: 'forms', label: 'Forms', value: sum.forms },
              { key: 'cookies', label: 'Cookies', value: sum.cookieNames },
              { key: 'secrets', label: 'Secrets', value: sum.secrets, tone: 'danger' },
              { key: 'sinks', label: 'Sinks', value: sum.sinks, tone: 'warn' },
            ];
            const total = STATS.reduce((n, s) => n + (s.value || 0), 0);
            return (
              <div className="inventory-section">
                <div className="checklist-head">
                  <h3>Site Inventory {currentHost && <span className="muted">· {currentHost}</span>}</h3>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button className="link-btn" onClick={refreshInventory}>Refresh</button>
                    <button className="link-btn" onClick={() => clearInventoryForHost(currentHost)} disabled={!currentHost || !inventory[currentHost]}>Clear</button>
                  </div>
                </div>
                <p className="checklist-sub">
                  Accumulated passively as you browse in-scope pages{passiveCapture ? '' : ' (capture is OFF — enable it in Config)'}.
                </p>
                <div className="inv-stats">
                  {STATS.map((s) => (
                    <div key={s.key} className={`inv-stat${!s.value ? ' zero' : s.tone ? ' tone-' + s.tone : ''}`}>
                      <span className="inv-stat-icon">{STAT_ICONS[s.key]}</span>
                      <span className="inv-stat-num">{s.value}</span>
                      <span className="inv-stat-label">{s.label}</span>
                    </div>
                  ))}
                </div>
                {total === 0 && (
                  <div className="recon-empty">
                    <span className="recon-empty-icon">{STAT_ICONS.endpoints}</span>
                    <p className="recon-empty-title">No inventory captured yet</p>
                    <p className="recon-empty-sub">
                      {passiveCapture
                        ? 'Browse in-scope pages on this host and the inventory fills in automatically — or run Passive Recon below.'
                        : 'Passive capture is off. Enable it in Config, then browse in-scope pages to build the inventory.'}
                    </p>
                  </div>
                )}
                {sum.pages > 0 && (
                  <details className="inv-details">
                    {sumHead('Pages', sum.pages)}
                    <div className="inv-list">{inv.pages.slice(0, 200).map((p, i) => <div key={i} className="inv-list-item"><code>{p}</code></div>)}</div>
                  </details>
                )}
                {sum.endpoints > 0 && (
                  <details className="inv-details">
                    {sumHead('Endpoints', sum.endpoints)}
                    <div className="inv-list">
                      {inv.endpoints.slice(0, 200).map((e, i) => (
                        <div key={i} className="inv-list-item"><code>{e}</code>
                          <span style={{ display: 'flex', gap: 4 }}>
                            <button className="btn-small" onClick={() => probeEndpoint(e)}>Probe</button>
                            {/\?/.test(e) && <button className="btn-small" onClick={() => runDifferentialProbe(e)} title="Boolean/timing differential probe on a query param">Diff</button>}
                          </span>
                        </div>
                      ))}
                    </div>
                  </details>
                )}
                {sum.params > 0 && (
                  <details className="inv-details">
                    {sumHead('Params', sum.params)}
                    <div className="inv-list">{inv.params.slice(0, 300).map((p, i) => <span key={i} className="tag">{p}</span>)}</div>
                  </details>
                )}
                {sum.scripts > 0 && (
                  <details className="inv-details">
                    {sumHead('Scripts', sum.scripts)}
                    <div className="inv-list">{inv.scripts.slice(0, 200).map((s, i) => <div key={i} className="inv-list-item"><code>{s}</code></div>)}</div>
                  </details>
                )}
                {sum.forms > 0 && (
                  <details className="inv-details">
                    {sumHead('Forms', sum.forms)}
                    <div className="inv-list">
                      {inv.forms.slice(0, 200).map((f, i) => (
                        <div key={i} className="inv-list-item" style={{ display: 'block' }}>
                          <span className="tag tag-fw">{(f.method || 'get').toUpperCase()}</span> <code>{f.action || '(self)'}</code>
                          {typeof f.fieldCount === 'number' && <span className="muted" style={{ fontSize: 10 }}> — {f.fieldCount} field(s)</span>}
                        </div>
                      ))}
                    </div>
                  </details>
                )}
                {sum.cookieNames > 0 && (
                  <details className="inv-details">
                    {sumHead('Cookies', sum.cookieNames)}
                    <div className="inv-list">{inv.cookieNames.slice(0, 300).map((c, i) => <span key={i} className="tag">{c}</span>)}</div>
                  </details>
                )}
                {sum.secrets > 0 && (
                  <details className="inv-details" open>
                    {sumHead('Secrets', sum.secrets, 'danger')}
                    <div className="inv-list">
                      {inv.secrets.slice(0, 200).map((s, i) => (
                        <div key={i} className="jswatch-secret">{s.type}: <code>{s.preview}</code></div>
                      ))}
                    </div>
                  </details>
                )}
                {sum.sinks > 0 && (
                  <details className="inv-details">
                    {sumHead('DOM-XSS sinks', sum.sinks, 'warn')}
                    <div className="inv-list">
                      {inv.sinks.slice(0, 200).map((s, i) => (
                        <div key={i} className="inv-list-item" style={{ display: 'block' }}>
                          <div>
                            <span className={`tag ${s.sources && s.sources.length ? 'tag-fw' : ''}`}>{s.sink}</span>
                            {s.sources && s.sources.length > 0 && <span className="muted" style={{ fontSize: 10 }}> ← {s.sources.join(', ')}</span>}
                          </div>
                          <code style={{ fontSize: 10 }}>{s.snippet}</code>
                        </div>
                      ))}
                    </div>
                  </details>
                )}
                {sum.updatedAt && <div className="muted" style={{ fontSize: 10, marginTop: 4 }}>Updated {new Date(sum.updatedAt).toLocaleString()}</div>}
              </div>
            );
          })()}

          {(() => {
            const hf = (currentHost && headerFindings[currentHost]) || null;
            const items = (hf && hf.findings) || [];
            const RANK = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
            const sorted = [...items].sort((a, b) => (RANK[a.severity] ?? 9) - (RANK[b.severity] ?? 9));
            return (
              <div className="inventory-section">
                <div className="checklist-head">
                  <h3>Security Headers {currentHost && <span className="muted">· {currentHost}</span>}</h3>
                  <button className="link-btn" onClick={() => clearHeaderFindingsForHost(currentHost)} disabled={!hf}>Clear</button>
                </div>
                <p className="checklist-sub">
                  Collected passively from response headers of in-scope traffic you generate — missing CSP, weak cookies,
                  permissive CORS, etc. Reload an in-scope page to populate.
                </p>
                {sorted.length === 0 ? (
                  <div className="hint">No header findings yet for this host. Browse an in-scope page and hit Refresh.</div>
                ) : (
                  <div className="header-findings">
                    {sorted.map((f, i) => (
                      <div key={i} className={`agent-finding sev-${f.severity}`}>
                        <span className="sev-badge">{f.severity}</span> <strong>{f.title}</strong>
                        {f.severity !== 'informational' && (
                          <button className="btn-small" style={{ float: 'right' }} onClick={() => draftFromFinding(f)}>Draft report</button>
                        )}
                        <div className="muted" style={{ fontSize: 10 }}>{f.evidence} · {f.ref}</div>
                      </div>
                    ))}
                    {hf.checkedAt && <div className="muted" style={{ fontSize: 10, marginTop: 4 }}>Updated {new Date(hf.checkedAt).toLocaleString()}</div>}
                  </div>
                )}
              </div>
            );
          })()}

          {(() => {
            const inv = (currentHost && inventory[currentHost]) || emptyInventory();
            const candidates = taintFindings(inv.sinks, currentHost);
            if (candidates.length === 0) return null;
            return (
              <div className="inventory-section">
                <div className="checklist-head">
                  <h3>DOM-XSS Candidates {currentHost && <span className="muted">· {currentHost}</span>}</h3>
                  <span className="muted" style={{ fontSize: 11 }}>{candidates.length} to review</span>
                </div>
                <p className="checklist-sub">
                  Sinks reachable from a controllable source, ranked by confidence. Candidates only — DOM-XSS needs
                  manual confirmation; never reported as-is.
                </p>
                <div className="header-findings">
                  {candidates.slice(0, 50).map((f, i) => (
                    <div key={i} className={`agent-finding sev-${f.severity}`}>
                      <span className="sev-badge">{f.severity}</span> <strong>{f.title}</strong>
                      <span className="muted" style={{ fontSize: 10 }}> · conf {f.confidence}</span>
                      <button className="btn-small" style={{ float: 'right' }} onClick={() => draftFromFinding(f)}>Draft report</button>
                      <div><code style={{ fontSize: 10 }}>{f.evidence}</code></div>
                    </div>
                  ))}
                </div>
              </div>
            );
          })()}

          <div className="inventory-section">
            <div className="checklist-head">
              <h3>JS Change Monitor</h3>
              <button className="btn-primary btn-small" onClick={runJsScan} disabled={jsScanning || !isHostAllowed(currentUrl)}>
                {jsScanning ? 'Scanning…' : 'Scan JS for Changes'}
              </button>
            </div>
            <p className="checklist-sub">
              Fetches this host's in-scope JS files, diffs them against the last snapshot, and
              alerts on new endpoints/secrets. Honors scope, dry-run &amp; rate limits.
            </p>
            {jsScanResult && jsScanResult.dryRun && (
              <div className="hint"><span className="recon-badge">Dry run</span> would fetch {jsScanResult.wouldFetch.length} file(s). Disable Dry Run in Config to diff.</div>
            )}
            {jsScanResult && jsScanResult.success && !jsScanResult.dryRun && (
              <div className="muted" style={{ fontSize: 11 }}>
                Scanned {jsScanResult.results.length} file(s) · {jsScanResult.interesting} with new surface.
              </div>
            )}
            {(() => {
              const history = (currentHost && jsWatch[currentHost]) || [];
              if (!history.length) return <div className="hint">No changes recorded yet. Scan once to snapshot, then again later to diff.</div>;
              return (
                <div className="jswatch-list">
                  {history.slice(0, 20).map((entry, i) => (
                    <div key={i} className="jswatch-entry">
                      <div className="muted" style={{ fontSize: 10 }}>{new Date(entry.ts).toLocaleString()}</div>
                      {entry.diffs.map((d, j) => (
                        <div key={j} className="jswatch-diff">
                          <div><code>{(() => { try { return new URL(d.url).pathname; } catch (_) { return d.url; } })()}</code> <span className="muted">{d.summary}</span></div>
                          {(d.addedEndpoints || []).slice(0, 8).map((ep, k) => (
                            <div key={k} className="jswatch-ep">+ <code>{ep}</code> <button className="btn-small" onClick={() => probeEndpoint(ep)}>Probe</button></div>
                          ))}
                          {(d.newSecrets || []).map((s, k) => (
                            <div key={k} className="jswatch-secret">{s.type}: <code>{s.preview}</code></div>
                          ))}
                        </div>
                      ))}
                    </div>
                  ))}
                </div>
              );
            })()}
          </div>

          <div className="inventory-section">
            <div className="checklist-head">
              <h3>Companion Agent</h3>
              <span className={`ai-dot ai-dot-${agentHealthInfo?.ok ? 'ok' : agentHealthInfo ? 'down' : 'checking'}`} title="Agent status" />
            </div>
            <p className="checklist-sub">
              Runs scope-gated recon tools in your local Docker agent. Configure the URL &amp; token in Config.
              Target: <code>{currentHost || '(open a target)'}</code>
            </p>
            <div className="agent-runner">
              <select value={agentTool} onChange={(e) => setAgentTool(e.target.value)}>
                <option value="subfinder">subfinder (safe)</option>
                <option value="dnsx">dnsx (safe)</option>
                <option value="httpx">httpx (safe)</option>
                <option value="gau">gau (safe)</option>
                <option value="waybackurls">waybackurls (safe)</option>
                <option value="naabu">naabu (active)</option>
                <option value="nmap">nmap (active)</option>
                <option value="nuclei">nuclei (active)</option>
                <option value="katana">katana (active)</option>
                <option value="ffuf">ffuf (active)</option>
                <option value="feroxbuster">feroxbuster (active)</option>
              </select>
              <select value={agentProfile} onChange={(e) => setAgentProfile(e.target.value)}>
                <option value="quick">quick</option>
                <option value="top1000">top1000</option>
                <option value="services">services (nmap)</option>
                <option value="deep">deep (crawl)</option>
              </select>
              <button className="btn-primary btn-small" onClick={runAgentScan} disabled={agentBusy || !isHostAllowed(currentUrl)}>
                {agentBusy ? 'Running…' : 'Run'}
              </button>
            </div>
            {agentResult && agentResult.error && (
              <div className="hint">Agent error: {agentResult.error}{agentResult.reason ? ` (${agentResult.reason})` : ''}</div>
            )}
            {agentResult && agentResult.ok !== undefined && (
              <div className="agent-result">
                <div className="muted" style={{ fontSize: 10 }}>
                  <code>{agentResult.command}</code> · {agentResult.durationMs}ms · exit {agentResult.exitCode}{agentResult.timedOut ? ' · timed out' : ''}
                </div>
                {agentResult.kind === 'findings' ? (
                  agentResult.items.length === 0 ? <div className="muted">No findings.</div> :
                  agentResult.items.slice(0, 100).map((f, i) => (
                    <div key={i} className={`agent-finding sev-${f.severity}`}>
                      <span className="sev-badge">{f.severity}</span> <strong>{f.name || f.templateId}</strong>
                      <div className="muted" style={{ fontSize: 10 }}>{f.matched}</div>
                    </div>
                  ))
                ) : agentResult.kind === 'http' ? (
                  agentResult.items.slice(0, 100).map((h, i) => (
                    <div key={i} className="agent-line"><code>{h.status}</code> {h.url} <span className="muted">{h.title}</span></div>
                  ))
                ) : agentResult.kind === 'ports' ? (
                  agentResult.items.slice(0, 200).map((p, i) => (
                    <div key={i} className="agent-line"><code>{p.port}</code> {p.service || p.host || ''} <span className="muted">{p.state || ''}</span></div>
                  ))
                ) : (
                  agentResult.items.slice(0, 300).map((line, i) => (
                    <div key={i} className="agent-line"><code>{typeof line === 'string' ? line : JSON.stringify(line)}</code></div>
                  ))
                )}
              </div>
            )}

            <div className="watches-block">
              <div className="checklist-head">
                <h4 style={{ margin: 0 }}>Scheduled Watches</h4>
                <button className="link-btn" onClick={loadWatches}>Refresh</button>
              </div>
              <p className="checklist-sub">
                Re-runs the selected tool on a schedule &amp; alerts on new findings (agent-side, deltas only).
              </p>
              <div className="agent-runner">
                <span className="muted" style={{ fontSize: 11, alignSelf: 'center' }}>every</span>
                <input
                  type="number" min={15} value={watchInterval}
                  onChange={(e) => setWatchInterval(Math.max(15, Number(e.target.value) || 360))}
                  style={{ width: 70 }}
                />
                <span className="muted" style={{ fontSize: 11, alignSelf: 'center' }}>min</span>
                <button className="btn-small" onClick={addWatch} disabled={!isHostAllowed(currentUrl)}>
                  Watch {agentTool} on {currentHost || '—'}
                </button>
              </div>
              {watchList.length === 0 ? (
                <div className="hint">No watches yet. Connect the agent (Config) and add one.</div>
              ) : (
                watchList.map((w) => (
                  <div key={w.id} className="watch-item">
                    <div className="watch-main">
                      <strong>{w.target}</strong> <span className="muted">[{(w.tools || []).join(', ')}]</span>
                      <div className="muted" style={{ fontSize: 10 }}>
                        every {w.intervalMinutes}m · {w.runs} run(s){w.lastSummary ? ` · ${w.lastSummary}` : ''}{w.running ? ' · running…' : ''}
                      </div>
                    </div>
                    <button className="btn-small" onClick={() => runWatch(w.id)}>Run</button>
                    <button className="btn-remove" onClick={() => deleteWatch(w.id)}>×</button>
                  </div>
                ))
              )}
            </div>
          </div>

          <h3>Page Recon</h3>
          <div className="controls">
            <button onClick={runRecon} disabled={reconLoading} className="btn-primary">
              {reconLoading ? 'Reading...' : 'Run Passive Recon'}
            </button>
            <button onClick={runDeepJsScan} disabled={deepJsScanning || !isHostAllowed(currentUrl)} className="btn-secondary">
              {deepJsScanning ? 'Scanning JS…' : 'Deep JS Scan'}
            </button>
            <button onClick={exportPageSource} className="btn-secondary">Export Source</button>
          </div>
          <p className="checklist-sub">
            Passive recon reads the loaded page (inline scripts only). Deep JS Scan additionally fetches this
            origin's external scripts and mines them for endpoints, secrets &amp; DOM-XSS sinks — results land in Site Inventory above.
          </p>

          {deepJsResult && (
            <div className="hint">
              Deep JS scan: {deepJsResult.scanned} same-origin script(s) · {deepJsResult.endpoints?.length || 0} endpoint(s) ·
              {' '}{deepJsResult.secrets?.length || 0} secret(s) · {deepJsResult.sinks?.length || 0} sink(s).
            </div>
          )}

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
                    <span style={{ display: 'flex', gap: 4 }}>
                      <button className="btn-small" onClick={() => probeEndpoint(ep)}>Probe</button>
                      {/\?/.test(ep) && <button className="btn-small" onClick={() => runDifferentialProbe(ep)} title="Boolean/timing differential probe on a query param">Diff</button>}
                    </span>
                  </div>
                ))}
              </div>

              {differentialResult && (
                <div className="recon-section">
                  <h4>Differential Probe</h4>
                  {differentialResult.dryRun ? (
                    <div className="muted" style={{ fontSize: 11 }}>
                      <span className="recon-badge">Dry run</span> on <code>{differentialResult.param}</code> — would GET {differentialResult.wouldFetch?.length} variant(s). Disable Dry Run to probe.
                    </div>
                  ) : differentialResult.success ? (
                    differentialResult.finding ? (
                      <div className={`agent-finding sev-${differentialResult.finding.severity}`}>
                        <span className="sev-badge">candidate</span> <strong>{differentialResult.finding.title}</strong>
                        <span className="muted" style={{ fontSize: 10 }}> · conf {differentialResult.finding.confidence}</span>
                        <button className="btn-small" style={{ float: 'right' }} onClick={() => draftFromFinding(differentialResult.finding)}>Draft report</button>
                        <div className="muted" style={{ fontSize: 10 }}>{differentialResult.finding.evidence}</div>
                      </div>
                    ) : (
                      <div className="muted" style={{ fontSize: 11 }}>No differential signal on <code>{differentialResult.param}</code>.</div>
                    )
                  ) : (
                    <div className="hint">Probe blocked: {differentialResult.reason}</div>
                  )}
                </div>
              )}

              {recon.secrets?.length > 0 && (
                <div className="recon-section">
                  <h4 className="h4-danger">Secrets in inline scripts ({recon.secrets.length})</h4>
                  {recon.secrets.map((s, i) => (
                    <div key={i} className="jswatch-secret">{s.type}: <code>{s.preview}</code></div>
                  ))}
                </div>
              )}

              {recon.sinks?.length > 0 && (
                <div className="recon-section">
                  <h4>DOM-XSS sinks ({recon.sinks.length})</h4>
                  {recon.sinks.slice(0, 50).map((s, i) => (
                    <div key={i} style={{ marginBottom: 4 }}>
                      <span className={`tag ${s.sources && s.sources.length ? 'tag-fw' : ''}`}>{s.sink}</span>
                      {s.sources && s.sources.length > 0 && <span className="muted" style={{ fontSize: 10 }}> ← {s.sources.join(', ')}</span>}
                      <div><code style={{ fontSize: 10 }}>{s.snippet}</code></div>
                    </div>
                  ))}
                </div>
              )}

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
                      <div key={i} className="muted"><span className="recon-badge">Dry run</span> would fetch: {u}</div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {activeTab === 'Findings' && (() => {
        const hostList = (currentHost && findings[currentHost]) || [];
        const all = findingsCrossHost ? Object.values(findings).flat() : hostList;
        // Score every finding through the validation gate, then sort (so ranking uses the recomputed confidence).
        const scored = sortFindings(validateFindings(dedupeFindings(all, { crossHost: findingsCrossHost })));
        // Confidence threshold: hide findings below the chosen band ('all' shows everything).
        const minConf = BANDS[findingsMinBand] || 0;
        const sorted = minConf ? scored.filter((f) => (f.confidence || 0) >= minConf) : scored;
        const hiddenCount = scored.length - sorted.length;
        const sum = summarizeFindings(sorted);
        const SEV = [
          { key: 'critical', label: 'Critical', value: sum.critical },
          { key: 'high', label: 'High', value: sum.high },
          { key: 'medium', label: 'Medium', value: sum.medium },
          { key: 'low', label: 'Low', value: sum.low },
          { key: 'informational', label: 'Info', value: sum.informational },
        ];
        const shieldCheck = (
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>
          </svg>
        );
        const docIcon = (
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/>
          </svg>
        );
        return (
          <div className="recon-panel find-tab">
            <div className="checklist-head">
              <h3>Findings {currentHost && !findingsCrossHost && <span className="muted">· {currentHost}</span>}</h3>
              <div style={{ display: 'flex', gap: 8 }}>
                <button className="link-btn" onClick={runProposeChains} disabled={chainsBusy || scored.length === 0} title="Ask AI to propose exploit chains across these findings (human-verified, nothing runs)">{chainsBusy ? '🔗 Proposing…' : '🔗 Propose chains'}</button>
                <button className="link-btn" onClick={refreshFindings}>Refresh</button>
                <button className="link-btn" onClick={() => clearFindingsForHost(currentHost)} disabled={!currentHost || !findings[currentHost]}>Clear host</button>
              </div>
            </div>
            <p className="checklist-sub">
              Unified from header analysis, DOM-XSS taint &amp; response oracles. Confidence reflects evidence strength — confirm before submitting.
            </p>

            <label className="find-toggle">
              <input type="checkbox" checked={findingsCrossHost} onChange={(e) => setFindingsCrossHost(e.target.checked)} />
              <span>Merge across all hosts <span className="find-toggle-sub">· program-wide dedup</span></span>
            </label>

            <label className="find-toggle">
              <span>Min confidence</span>
              <select value={findingsMinBand} onChange={(e) => setFindingsMinBand(e.target.value)}>
                <option value="all">All</option>
                <option value="tentative">Tentative+ (≥{BANDS.tentative})</option>
                <option value="likely">Likely+ (≥{BANDS.likely})</option>
                <option value="confirmed">Confirmed (≥{BANDS.confirmed})</option>
              </select>
              {hiddenCount > 0 && <span className="find-toggle-sub">· {hiddenCount} hidden</span>}
            </label>

            <div className="find-sevbar" role="list" aria-label="Findings by severity">
              {SEV.map((s) => (
                <div key={s.key} role="listitem" className={`find-sev sev-${s.key}${s.value ? '' : ' zero'}`}>
                  <span className="find-sev-num">{s.value}</span>
                  <span className="find-sev-label">{s.label}</span>
                </div>
              ))}
            </div>

            {sorted.length === 0 && scored.length > 0 ? (
              <div className="find-empty">
                <span className="find-empty-icon">{shieldCheck}</span>
                <p className="find-empty-title">All findings filtered out</p>
                <p className="find-empty-sub">{scored.length} finding{scored.length === 1 ? ' is' : 's are'} below the “{findingsMinBand}” confidence threshold. <button className="link-btn" onClick={() => setFindingsMinBand('all')}>Show all</button></p>
              </div>
            ) : sorted.length === 0 ? (
              <div className="find-empty">
                <span className="find-empty-icon">{shieldCheck}</span>
                <p className="find-empty-title">No findings yet</p>
                <p className="find-empty-sub">Run a Deep JS Scan, browse in-scope pages to collect header findings, or Diff an endpoint on the Recon tab.</p>
              </div>
            ) : (
              <div className="find-list">
                {sorted.map((f, i) => {
                  const depth = Number(f.depth) || 0;
                  const notNoise = canEscalateFinding(f, { minBand: 'tentative' });
                  const canEsc = canEscalate({ depth, budgetUsed: escBudgetUsed }) && notNoise;
                  const band = f.validation && f.validation.band;
                  return (
                    <div key={i} className={`find-card sev-${f.severity}`}>
                      <div className="find-card-top">
                        <span className={`find-sevtag sev-${f.severity}`}>{f.severity}</span>
                        <strong className="find-card-title">{f.title}</strong>
                      </div>
                      <div className="find-card-meta">
                        {typeof f.confidence === 'number' && <span className={`find-conf${band ? ` band-${band}` : ''}`}>{f.confidence}%{band ? ` · ${band}` : ''}</span>}
                        {findingsCrossHost && f.host && <span className="find-host">{f.host}</span>}
                        <span className="find-type">{f.type}{f.ref ? ` · ${f.ref}` : ''}</span>
                      </div>
                      {f.evidence && <code className="find-evidence">{f.evidence}</code>}
                      <div className="find-card-actions">
                        <button
                          className="find-act"
                          disabled={escalationBusy || !canEsc}
                          onClick={() => runEscalate(f)}
                          title={canEsc ? 'Ask AI for next steps to escalate this finding' : 'Escalation limit reached (max depth or session budget)'}
                        >
                          <IconBolt />Escalate{depth > 0 ? ` · d${depth}` : ''}
                        </button>
                        <button className="find-act primary" onClick={() => draftFromFinding(f)}>
                          {docIcon}Draft report
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        );
      })()}

      {activeTab === 'Checklist' && (() => {
        const summary = summarizeProgress(checklistProgress);
        const c = summary.counts;
        const total = summary.total || 1;
        const pctOf = (n) => `${(n / total) * 100}%`;
        const STATE_META = {
          todo:    { label: 'To do' },
          testing: { label: 'Testing' },
          pass:    { label: 'Pass' },
          finding: { label: 'Finding' },
          na:      { label: 'N/A' },
        };
        const LEGEND = [['finding', 'Findings'], ['pass', 'Pass'], ['testing', 'Testing'], ['todo', 'To do'], ['na', 'N/A']];
        return (
          <div className="checklist-panel">
            <div className="checklist-head">
              <h3><IconChecklist />Methodology</h3>
              <button className="link-btn" onClick={resetChecklist} disabled={!currentHost}>Reset</button>
            </div>
            <p className="checklist-sub">
              Tracking for <code>{currentHost || '(open an http(s) page)'}</code>. Progress is saved
              per target. WSTG / OWASP-API / zseano — a guide of what to test, nothing auto-fires.
            </p>

            <div className="ck-progress">
              <div className="ck-progress-top">
                <span className="ck-pct">{summary.percentComplete}%</span>
                <span className="ck-pct-label">of {summary.total} checks touched</span>
                {c.finding > 0 && <span className="ck-findings">{c.finding} finding{c.finding === 1 ? '' : 's'}</span>}
              </div>
              <div className="ck-bar" role="img" aria-label={`${summary.percentComplete}% of checks touched`}>
                {['pass', 'finding', 'testing', 'na'].map((s) => (c[s] > 0
                  ? <div key={s} className={`ck-seg ck-${s}`} style={{ width: pctOf(c[s]) }} />
                  : null))}
              </div>
              <div className="ck-legend">
                {LEGEND.map(([s, label]) => (
                  <span key={s} className="ck-leg"><span className={`ck-dot ck-${s}`} /><b>{c[s]}</b> {label}</span>
                ))}
              </div>
            </div>

            {CHECKLIST.map((cat) => {
              const open = openCategories.has(cat.id);
              const done = cat.items.filter((it) => (checklistProgress[it.id] || 'todo') !== 'todo').length;
              const hasFinding = cat.items.some((it) => checklistProgress[it.id] === 'finding');
              return (
                <div key={cat.id} className="ck-cat">
                  <button className={`ck-cat-head${open ? ' open' : ''}`} onClick={() => toggleCategory(cat.id)} aria-expanded={open}>
                    <span className="ck-caret" aria-hidden="true"><IconChevron /></span>
                    <span className="ck-cat-name">{cat.name}</span>
                    {hasFinding && <span className="ck-cat-flag" title="Has a finding" />}
                    <span className="ck-cat-mini" aria-hidden="true"><span className="ck-cat-mini-fill" style={{ width: `${(done / cat.items.length) * 100}%` }} /></span>
                    <span className="ck-cat-count">{done}/{cat.items.length}</span>
                  </button>
                  {open && (
                    <div className="ck-items">
                      {cat.items.map((item) => {
                        const state = checklistProgress[item.id] || 'todo';
                        return (
                          <div key={item.id} className={`ck-item ck-item-${state}`}>
                            <div className="ck-item-top">
                              <span className={`ck-status ck-${state}`} title={STATE_META[state].label} aria-label={STATE_META[state].label} />
                              <span className="ck-ref">{item.ref}</span>
                              <span className="ck-title">{item.title}</span>
                              <span className="ck-item-actions">
                                {item.payloadKey && (
                                  <button className="ck-link" title="Load preset payloads for this test" onClick={() => jumpToPayload(item.payloadKey)}>Payloads</button>
                                )}
                                <button className="ck-link" title="Draft a report for this finding" onClick={() => openReportDraft(item, cat.name)}>Report</button>
                              </span>
                            </div>
                            <div className="ck-states" role="group" aria-label="Set status">
                              {CHECKLIST_STATES.map((s) => (
                                <button
                                  key={s}
                                  className={`ck-state ck-${s}${state === s ? ' active' : ''}`}
                                  onClick={() => setChecklistItemState(item.id, s)}
                                  aria-pressed={state === s}
                                >
                                  {STATE_META[s].label}
                                </button>
                              ))}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        );
      })()}

            {activeTab === 'Programs' && (() => {
        const overall = summarizeSubmissions(submissions);
        const rolled = summarizeByProgram(programs, submissions);
        const progName = (id) => (programs.find((p) => p.id === id) || {}).name || '—';
        const SEV_ABBR = { critical: 'CRIT', high: 'HIGH', medium: 'MED', low: 'LOW', informational: 'INFO' };
        const sevClass = (s) => `sev-${SEVERITIES.includes(s) ? s : 'informational'}`;
        const stateClass = (st) => `st-${(st || 'draft').replace(/[^a-z]/gi, '')}`;
        const money = (n) => `$${Number(n || 0).toLocaleString()}`;
        return (
          <div className="programs-panel">
            <div className="settings-header">
              <div className="settings-header-icon"><IconPrograms /></div>
              <div className="settings-header-text">
                <h3>Programs &amp; Payouts</h3>
                <p className="settings-header-sub">Track the programs you hunt, your submissions, and what they pay.</p>
              </div>
            </div>

            <div className="inv-stats prog-stats">
              <div className={`inv-stat tone-success${overall.earned === 0 ? ' zero' : ''}`}>
                <span className="inv-stat-icon"><IconDollar /></span>
                <span className="inv-stat-num">{money(overall.earned)}</span><span className="inv-stat-label">Earned</span>
              </div>
              <div className={`inv-stat tone-accent${overall.paidCount === 0 ? ' zero' : ''}`}>
                <span className="inv-stat-icon"><IconCheckCircle /></span>
                <span className="inv-stat-num">{overall.paidCount}</span><span className="inv-stat-label">Paid</span>
              </div>
              <div className={`inv-stat tone-warn${overall.pipeline === 0 ? ' zero' : ''}`}>
                <span className="inv-stat-icon"><IconHistory /></span>
                <span className="inv-stat-num">{overall.pipeline}</span><span className="inv-stat-label">Pipeline</span>
              </div>
              <div className={`inv-stat${overall.total === 0 ? ' zero' : ''}`}>
                <span className="inv-stat-icon"><IconLayers /></span>
                <span className="inv-stat-num">{overall.total}</span><span className="inv-stat-label">Total</span>
              </div>
            </div>

            <section className="settings-group">
              <div className="settings-group-head">
                <span className="settings-group-icon"><IconPlus /></span>
                <h4>Add Program</h4>
              </div>
              <div className="settings-card">
                <div className="prog-form-row">
                  <input placeholder="Program name" value={progForm.name} onChange={(e) => setProgForm({ ...progForm, name: e.target.value })} />
                  <select value={progForm.platform} onChange={(e) => setProgForm({ ...progForm, platform: e.target.value })}>
                    {PLATFORMS.map((p) => <option key={p} value={p}>{p}</option>)}
                  </select>
                </div>
                <div className="prog-form-row">
                  <input placeholder="Program URL (optional)" value={progForm.url} onChange={(e) => setProgForm({ ...progForm, url: e.target.value })} />
                  <button className="btn-primary btn-sm" onClick={addProgram}>Add</button>
                </div>
              </div>
            </section>

            {programs.length > 0 && (
              <section className="settings-group">
                <div className="settings-group-head">
                  <span className="settings-group-icon"><IconChecklist /></span>
                  <h4>Log a Submission</h4>
                </div>
                <div className="settings-card">
                  <div className="prog-form-row">
                    <select value={subForm.programId} onChange={(e) => setSubForm({ ...subForm, programId: e.target.value })}>
                      <option value="">— program —</option>
                      {programs.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
                    </select>
                    <input placeholder="Finding title" value={subForm.title} onChange={(e) => setSubForm({ ...subForm, title: e.target.value })} />
                  </div>
                  <div className="prog-form-row">
                    <select value={subForm.severity} onChange={(e) => setSubForm({ ...subForm, severity: e.target.value })}>
                      {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
                    </select>
                    <select value={subForm.state} onChange={(e) => setSubForm({ ...subForm, state: e.target.value })}>
                      {SUBMISSION_STATES.map((s) => <option key={s} value={s}>{s}</option>)}
                    </select>
                    <input className="bounty-input" type="number" placeholder="$ bounty" value={subForm.bounty} onChange={(e) => setSubForm({ ...subForm, bounty: e.target.value })} />
                    <button className="btn-primary btn-sm" onClick={addSubmission}>Log</button>
                  </div>
                </div>
              </section>
            )}

            {rolled.length > 0 && (
              <section className="settings-group">
                <div className="settings-group-head">
                  <span className="settings-group-icon"><IconPrograms /></span>
                  <h4>Programs</h4>
                  <span className="settings-group-meta">{rolled.length}</span>
                </div>
                <div className="prog-list">
                  {rolled.map((p) => (
                    <div key={p.id} className="prog-card">
                      <div className="prog-card-main">
                        <div className="prog-card-top">
                          <strong className="prog-card-name">{p.name}</strong>
                          <span className="platform-tag">{p.platform}</span>
                          {p.url && (
                            <a className="prog-link" href={p.url} target="_blank" rel="noopener noreferrer" title="Open program" aria-label="Open program page">
                              <IconExternalLink />
                            </a>
                          )}
                        </div>
                        <div className="prog-chips">
                          <span className="prog-chip earn"><IconDollar />{money(p.summary.earned)}</span>
                          <span className="prog-chip">{p.submissionCount} sub{p.submissionCount === 1 ? '' : 's'}</span>
                          {p.summary.pipeline > 0 && <span className="prog-chip open">{p.summary.pipeline} open</span>}
                        </div>
                      </div>
                      <button className="icon-remove" onClick={() => deleteProgram(p.id)} title="Delete program" aria-label="Delete program">×</button>
                    </div>
                  ))}
                </div>
              </section>
            )}

            {submissions.length > 0 && (
              <section className="settings-group">
                <div className="settings-group-head">
                  <span className="settings-group-icon"><IconChecklist /></span>
                  <h4>Submissions</h4>
                  <span className="settings-group-meta">{submissions.length}</span>
                </div>
                <div className="prog-list">
                  {submissions.map((s) => (
                    <div key={s.id} className="prog-card sub-card">
                      <div className="prog-card-main">
                        <div className="prog-card-top">
                          <span className={`find-sevtag ${sevClass(s.severity)}`}>{SEV_ABBR[s.severity] || 'INFO'}</span>
                          <strong className="prog-card-name">{s.title}</strong>
                        </div>
                        <div className="prog-chips">
                          <span className="prog-chip">{progName(s.programId)}</span>
                          {s.bounty > 0 && <span className="prog-chip earn"><IconDollar />{money(s.bounty)}</span>}
                        </div>
                      </div>
                      <select
                        value={s.state}
                        onChange={(e) => setSubmissionState(s.id, e.target.value)}
                        className={`sub-state ${stateClass(s.state)}`}
                        aria-label={`State for ${s.title}`}
                      >
                        {SUBMISSION_STATES.map((st) => <option key={st} value={st}>{st}</option>)}
                      </select>
                      <button className="icon-remove" onClick={() => deleteSubmission(s.id)} title="Delete submission" aria-label="Delete submission">×</button>
                    </div>
                  ))}
                </div>
              </section>
            )}

            {programs.length === 0 && (
              <div className="prog-empty">
                <div className="prog-empty-icon"><IconTrophy /></div>
                <div className="prog-empty-title">No programs yet</div>
                <div className="prog-empty-sub">Add a program above to start tracking submissions, pipeline and payouts.</div>
              </div>
            )}
          </div>
        );
      })()}

      {activeTab === 'AI' && (() => {
        const chatHost = (() => { try { return currentUrl ? new URL(currentUrl).host : ''; } catch (_) { return ''; } })();
        const fieldCount = Array.isArray(elements) ? elements.length : 0;
        const STARTERS = [
          { cat: 'Analyze', icon: <IconScan />, label: 'Break down an XSS payload',
            prompt: 'Explain this payload step by step and suggest a stronger variant: <script>alert(1)</script>' },
          { cat: 'Generate', icon: <IconWand />, label: 'Craft a SQLi login bypass',
            prompt: 'Give me an effective SQL injection payload for a login form and explain exactly why it works.' },
          { cat: 'Escalate', icon: <IconTarget />, label: 'Turn reflected XSS into impact',
            prompt: 'How do I escalate a reflected XSS into a high-impact finding worth reporting? Give concrete next steps.' },
          { cat: 'Learn', icon: <IconBook />, label: 'What to test on this page',
            prompt: chatHost
              ? `I'm testing ${chatHost}${fieldCount ? ` and found ${fieldCount} input field(s)` : ''}. What vulnerability classes should I prioritize and how?`
              : 'I found a page with a file upload and a search box. What vulnerability classes should I prioritize and how?' },
        ];
        return (
        <div className="ai-panel">
          <div className="ai-header">
            <div className="ai-header-main">
              <span className="ai-avatar" aria-hidden="true"><IconAI /></span>
              <div className="ai-titles">
                <h3>AI Assistant</h3>
                <p>Explain, critique &amp; craft payloads for the page you're testing</p>
              </div>
            </div>
            <div className="ai-header-actions">
              <select
                className="ai-model-mini"
                value={aiModel}
                onChange={(e) => onSelectModel(e.target.value)}
                aria-label="AI model"
                title="AI model"
                disabled={chatBusy}
              >
                {aiModels.map((m) => (
                  <option key={m.id} value={m.id}>{m.label}</option>
                ))}
              </select>
              <button
                type="button"
                className="ai-clear"
                onClick={() => setChatMessages([])}
                disabled={chatBusy || chatMessages.length === 0}
                title="Clear conversation"
              >
                Clear
              </button>
            </div>
          </div>

          {chatHost && (
            <div className="ai-context" title="The AI can reason about the page you have open">
              <span className={`ai-context-dot${fieldCount ? ' live' : ''}`} />
              <span className="ai-context-host">{chatHost}</span>
              {fieldCount > 0 && <span className="ai-context-meta">{fieldCount} field{fieldCount === 1 ? '' : 's'} in scope</span>}
            </div>
          )}

          <div className="ai-log" ref={chatLogRef} role="log" aria-live="polite" aria-label="AI conversation">
            {chatMessages.length === 0 && (
              <div className="ai-welcome">
                <p className="ai-welcome-lead">Ask anything about testing this page — or start with:</p>
                <div className="ai-suggest-grid">
                  {STARTERS.map((s, i) => (
                    <button key={i} type="button" className="ai-suggest" onClick={() => sendChat(s.prompt)}>
                      <span className="ai-suggest-icon">{s.icon}</span>
                      <span className="ai-suggest-text">
                        <span className="ai-suggest-cat">{s.cat}</span>
                        <span className="ai-suggest-label">{s.label}</span>
                      </span>
                    </button>
                  ))}
                </div>
              </div>
            )}
            {chatMessages.map((m, i) => (
              m.role === 'user' ? (
                <div key={i} className="ai-row ai-row-user">
                  <div className="ai-bubble ai-bubble-user">{m.content}</div>
                </div>
              ) : (
                <div key={i} className="ai-row ai-row-assistant">
                  <span className="ai-avatar ai-avatar-msg" aria-hidden="true"><IconAI /></span>
                  <div className="ai-bubble-wrap">
                    <div className="ai-bubble ai-bubble-assistant">{renderMessage(m.content, useCodeAsPayload)}</div>
                    <div className="ai-msg-actions">
                      <CopyButton text={m.content} className="ai-icon-btn" title="Copy reply" />
                    </div>
                  </div>
                </div>
              )
            ))}
            {chatBusy && (
              <div className="ai-row ai-row-assistant">
                <span className="ai-avatar ai-avatar-msg" aria-hidden="true"><IconAI /></span>
                <div className="ai-bubble ai-bubble-assistant ai-typing" aria-label="AI is thinking">
                  <span className="ai-typing-dot" /><span className="ai-typing-dot" /><span className="ai-typing-dot" />
                </div>
              </div>
            )}
          </div>

          <div className="ai-composer">
            <textarea
              rows={1}
              placeholder="Paste a payload or ask a question…"
              value={chatInput}
              onChange={(e) => setChatInput(e.target.value)}
              onInput={(e) => { e.target.style.height = 'auto'; e.target.style.height = Math.min(e.target.scrollHeight, 132) + 'px'; }}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault();
                  if (chatInput.trim() && !chatBusy) { e.target.style.height = 'auto'; sendChat(); }
                }
              }}
              disabled={chatBusy}
              aria-label="Message the AI assistant"
            />
            <button
              type="button"
              className="ai-send"
              onClick={() => sendChat()}
              disabled={chatBusy || !chatInput.trim()}
              aria-label="Send message"
              title="Send (Enter)"
            >
              <IconSend />
            </button>
          </div>
          <div className="ai-composer-hint">
            <span><kbd>Enter</kbd> to send · <kbd>Shift</kbd>+<kbd>Enter</kbd> for newline</span>
            {aiReachable === false && <span className="ai-offline">Proxy unreachable — check the Edge Function &amp; login</span>}
          </div>
        </div>
        );
      })()}

      {activeTab === 'History' && (() => {
        const vulnTypes = Array.from(new Set(payloadHistory.map((h) => h.vuln || 'custom')));
        const q = historyQuery.trim().toLowerCase();
        const rows = payloadHistory
          .map((entry, originalIndex) => ({ entry, originalIndex }))
          .filter(({ entry }) => historyFilter === 'all' || (entry.vuln || 'custom') === historyFilter)
          .filter(({ entry }) => {
            if (!q) return true;
            const hay = [vulnLabel(entry.vuln), entry.payloadSource, ...(entry.payloads || [])]
              .join(' ')
              .toLowerCase();
            return hay.includes(q);
          });

        return (
          <div className="history-panel">
            <div className="history-head">
              <div className="history-title">
                <IconHistory />
                <span>History</span>
                {payloadHistory.length > 0 && (
                  <span className="history-count">{payloadHistory.length}</span>
                )}
              </div>
              {payloadHistory.length > 0 && (
                <button className="history-clear" onClick={clearPayloadHistory} aria-label="Clear all history">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="3 6 5 6 21 6" /><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
                  </svg>
                  Clear all
                </button>
              )}
            </div>

            {payloadHistory.length === 0 ? (
              <div className="history-empty">
                <div className="history-empty-icon">
                  <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M3 3v5h5" /><path d="M3.05 13A9 9 0 1 0 6 5.3L3 8" /><path d="M12 7v5l4 2" />
                  </svg>
                </div>
                <div className="history-empty-title">No history yet</div>
                <div className="history-empty-sub">Run a payload test and it will be saved here for quick reuse.</div>
              </div>
            ) : (
              <>
                <div className="history-search">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" />
                  </svg>
                  <input
                    type="text"
                    value={historyQuery}
                    onChange={(e) => setHistoryQuery(e.target.value)}
                    placeholder="Search payloads or source…"
                    aria-label="Search history"
                  />
                  {historyQuery && (
                    <button className="history-search-clear" onClick={() => setHistoryQuery('')} aria-label="Clear search">
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
                      </svg>
                    </button>
                  )}
                </div>

                {vulnTypes.length > 1 && (
                  <div className="history-chips">
                    <button
                      className={'history-chip' + (historyFilter === 'all' ? ' active' : '')}
                      onClick={() => setHistoryFilter('all')}
                    >
                      All
                    </button>
                    {vulnTypes.map((t) => (
                      <button
                        key={t}
                        className={'history-chip' + (historyFilter === t ? ' active' : '')}
                        onClick={() => setHistoryFilter(t)}
                      >
                        {vulnLabel(t)}
                      </button>
                    ))}
                  </div>
                )}

                {rows.length === 0 ? (
                  <div className="history-empty small">
                    <div className="history-empty-title">No matches</div>
                    <div className="history-empty-sub">Try a different search term or filter.</div>
                  </div>
                ) : (
                  <div className="history-list">
                    {rows.map(({ entry: h, originalIndex }) => {
                      const payloads = h.payloads || [];
                      const shown = payloads.slice(0, 5);
                      const extra = payloads.length - shown.length;
                      const targetsCount = (h.targets || []).length;
                      const copied = copiedHistoryIdx === originalIndex;
                      return (
                        <div key={originalIndex} className="history-item" data-vuln={h.vuln || 'custom'}>
                          <div className="history-item-top">
                            <div className="history-item-head">
                              <span className="vuln-badge" data-vuln={h.vuln || 'custom'}>{vulnLabel(h.vuln)}</span>
                              <span className="history-time" title={new Date(h.timestamp).toLocaleString()}>
                                {formatRelativeTime(h.timestamp)}
                              </span>
                            </div>
                            <div className="history-actions">
                              <button className="hicon" title="Insert into Payloads tab" aria-label="Insert into Payloads tab" onClick={() => insertHistoryEntry(h)}>
                                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                  <polyline points="9 10 4 15 9 20" /><path d="M20 4v7a4 4 0 0 1-4 4H4" />
                                </svg>
                              </button>
                              <button className={'hicon' + (copied ? ' ok' : '')} title={copied ? 'Copied' : 'Copy payloads'} aria-label="Copy payloads" onClick={() => copyHistoryEntry(h, originalIndex)}>
                                {copied ? <IconCheck /> : <IconCopy />}
                              </button>
                              <button className="hicon danger" title="Delete entry" aria-label="Delete entry" onClick={() => deleteHistoryEntry(originalIndex)}>
                                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                  <polyline points="3 6 5 6 21 6" /><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
                                </svg>
                              </button>
                            </div>
                          </div>
                          <div className="history-tags">
                            <span className="htag">
                              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                <path d="m12 2 9 5-9 5-9-5 9-5z" /><path d="m3 12 9 5 9-5" /><path d="m3 17 9 5 9-5" />
                              </svg>
                              {payloads.length} {payloads.length === 1 ? 'payload' : 'payloads'}
                            </span>
                            {targetsCount > 0 && (
                              <span className="htag">
                                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                  <circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="4.5" /><circle cx="12" cy="12" r="1" fill="currentColor" stroke="none" />
                                </svg>
                                {targetsCount} {targetsCount === 1 ? 'target' : 'targets'}
                              </span>
                            )}
                            {h.payloadSource && <span className="htag src">{h.payloadSource}</span>}
                          </div>
                          <pre className="history-payload">{shown.join('\n')}{extra > 0 ? `\n+${extra} more…` : ''}</pre>
                        </div>
                      );
                    })}
                  </div>
                )}
              </>
            )}
          </div>
        );
      })()}

      {activeTab === 'Settings' && (() => {
        const scopeState = currentHost ? scopeStatus(currentUrl) : null;
        return (
        <div className="settings-panel">
          <div className="settings-header">
            <div className="settings-header-icon"><IconConfig /></div>
            <div className="settings-header-text">
              <h3>Configuration</h3>
              <p className="settings-header-sub">Scope, safety, automation and integrations for this workspace.</p>
            </div>
          </div>

          {/* ── Safety: the master gate, always up top ── */}
          <div className={`safety-card${dryRunMode ? ' is-safe' : ' is-live'}`}>
            <div className="safety-icon">{dryRunMode ? <IconShield /> : <IconBolt />}</div>
            <div className="safety-body">
              <div className="safety-title-row">
                <span className="safety-title">Dry Run Mode</span>
                <span className={`safety-badge${dryRunMode ? '' : ' live'}`}>{dryRunMode ? 'Safe' : 'Live'}</span>
              </div>
              <p className="safety-desc">
                {dryRunMode
                  ? 'Active requests are simulated — nothing is sent to targets.'
                  : 'Live mode — probes and payloads execute against in-scope targets.'}
              </p>
            </div>
            <Toggle checked={dryRunMode} onChange={() => toggleDryRun()} label="Toggle Dry Run Mode" tone="safety" />
          </div>

          {/* ── Program Scope ── */}
          <section className="settings-group">
            <div className="settings-group-head">
              <span className="settings-group-icon"><IconTarget /></span>
              <h4>Program Scope</h4>
              {scopeState && (
                <span className={`scope-pill${scopeState.allowed ? ' ok' : ' bad'}`}>
                  <span className="scope-pill-dot" />
                  {scopeState.allowed ? 'in scope' : scopeState.reason.replace(/_/g, ' ')}
                </span>
              )}
            </div>
            <div className="settings-card">
              <p className="scope-help">
                One host pattern per line. <code>*.example.com</code> = apex + subdomains,
                <code>example.com</code> = exact host, <code>*</code> = everything.
                Out-of-scope always wins. Enforced before any scan, probe or capture.
              </p>
              <label className="scope-label"><span className="scope-dot in" />In scope</label>
              <textarea
                className="scope-textarea"
                rows={4}
                value={scopeInText}
                onChange={(e) => setScopeInText(e.target.value)}
                placeholder={'*.example.com\napi.example.com'}
                spellCheck={false}
              />
              <label className="scope-label"><span className="scope-dot out" />Out of scope</label>
              <textarea
                className="scope-textarea"
                rows={3}
                value={scopeOutText}
                onChange={(e) => setScopeOutText(e.target.value)}
                placeholder={'admin.example.com\n*.dev.example.com'}
                spellCheck={false}
              />
              <div className="scope-foot">
                <div className="scope-current muted">
                  {currentHost
                    ? <>Current: <code>{currentHost}</code></>
                    : 'Open an http(s) page to see its scope status.'}
                </div>
                <button onClick={saveScope} className="btn-primary btn-sm">Save Scope</button>
              </div>
            </div>
          </section>

          {/* ── Data Collection ── */}
          <section className="settings-group">
            <div className="settings-group-head">
              <span className="settings-group-icon"><IconEye /></span>
              <h4>Data Collection</h4>
            </div>
            <div className="settings-card">
              <div className="setting-row">
                <div className="setting-row-text">
                  <div className="setting-row-label">Passive capture</div>
                  <div className="setting-row-desc">Record endpoints, params and JS as you browse in-scope targets.</div>
                </div>
                <Toggle checked={passiveCapture} onChange={togglePassiveCapture} label="Toggle passive capture" />
              </div>
            </div>
          </section>

          {/* ── Notifications ── */}
          <section className="settings-group">
            <div className="settings-group-head">
              <span className="settings-group-icon"><IconBell /></span>
              <h4>Notifications</h4>
            </div>
            <div className="settings-card">
              <div className="setting-row">
                <div className="setting-row-text">
                  <div className="setting-row-label">New surface alerts</div>
                  <div className="setting-row-desc">Alert on new JS endpoints / secrets (deltas only).</div>
                </div>
                <Toggle
                  checked={notifyConfig.enabled}
                  onChange={(v) => saveNotifyConfig({ ...notifyConfig, enabled: v })}
                  label="Toggle new-surface alerts"
                />
              </div>
              <div className={`setting-subfields${notifyConfig.enabled ? '' : ' is-dim'}`}>
                <div className="field-pair">
                  <select
                    className="settings-select"
                    value={notifyConfig.webhookPlatform}
                    onChange={(e) => saveNotifyConfig({ ...notifyConfig, webhookPlatform: e.target.value })}
                  >
                    {WEBHOOK_PLATFORMS.map((p) => <option key={p} value={p}>{p}</option>)}
                  </select>
                  <input
                    type="text"
                    placeholder="Optional webhook URL (Discord / Slack / Telegram)"
                    value={notifyConfig.webhookUrl}
                    onChange={(e) => saveNotifyConfig({ ...notifyConfig, webhookUrl: e.target.value })}
                  />
                </div>
                <div className="scope-help">Leave the webhook blank for local Chrome notifications only.</div>
              </div>
            </div>
          </section>

          {/* ── Background JS Monitor ── */}
          <section className="settings-group">
            <div className="settings-group-head">
              <span className="settings-group-icon"><IconRefresh /></span>
              <h4>Background JS Monitor</h4>
            </div>
            <div className="settings-card">
              <div className="setting-row">
                <div className="setting-row-text">
                  <div className="setting-row-label">Scheduled re-scan</div>
                  <div className="setting-row-desc">Auto re-scan tracked hosts on a schedule. Paused while Dry Run is on.</div>
                </div>
                <Toggle
                  checked={jsMonitor.enabled}
                  onChange={(v) => saveJsMonitor({ ...jsMonitor, enabled: v })}
                  label="Toggle background JS monitor"
                />
              </div>
              <div className={`setting-subfields${jsMonitor.enabled ? '' : ' is-dim'}`}>
                <div className="interval-field">
                  <input
                    type="number"
                    min={15}
                    value={jsMonitor.intervalMinutes}
                    onChange={(e) => saveJsMonitor({ ...jsMonitor, intervalMinutes: Math.max(15, Number(e.target.value) || 360) })}
                  />
                  <span className="interval-unit">minutes between scans</span>
                  <span className="interval-min">min 15</span>
                </div>
              </div>
            </div>
          </section>

          {/* ── Companion Agent ── */}
          <section className="settings-group">
            <div className="settings-group-head">
              <span className="settings-group-icon"><IconServer /></span>
              <h4>Companion Agent</h4>
              {agentHealthInfo && (
                <span className={`scope-pill${agentHealthInfo.ok ? ' ok' : agentHealthInfo.loading ? ' pending' : ' bad'}`}>
                  <span className="scope-pill-dot" />
                  {agentHealthInfo.loading ? 'checking' : agentHealthInfo.ok ? 'connected' : 'offline'}
                </span>
              )}
            </div>
            <div className="settings-card">
              <p className="scope-help">
                The local Docker tool-runner. See <code>agent/README.md</code>. Runs on
                <code>127.0.0.1:8787</code> by default.
              </p>
              <label className="scope-label">Agent URL</label>
              <input
                type="text"
                className="agent-input"
                value={agentConfig.url}
                onChange={(e) => saveAgentConfig({ ...agentConfig, url: e.target.value })}
                placeholder="http://localhost:8787"
              />
              <label className="scope-label">Token</label>
              <input
                type="password"
                className="agent-input"
                value={agentConfig.token}
                onChange={(e) => saveAgentConfig({ ...agentConfig, token: e.target.value })}
                placeholder="AGENT_TOKEN from your .env"
              />
              <div className="agent-actions">
                <button className="btn-small" onClick={checkAgentHealth}>Check Health</button>
                <button className="btn-small" onClick={syncAgentScope}>Sync Scope</button>
              </div>
              {agentHealthInfo && agentHealthInfo.ok && (
                <div className="agent-health">
                  <div className="muted" style={{ fontSize: 11 }}>Active tools: {agentHealthInfo.allowActive ? 'on' : 'off'}</div>
                  <div className="agent-tools">
                    {(agentHealthInfo.tools || []).map((t) => (
                      <span key={t.name} className={`tag ${t.available ? '' : 'tag-off'}`} title={t.risk}>
                        {t.available ? '✓' : '✗'} {t.name}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {agentHealthInfo && agentHealthInfo.ok === false && !agentHealthInfo.loading && (
                <div className="hint">Unreachable. Start it with <code>docker compose up</code> in <code>agent/</code>.</div>
              )}
            </div>
          </section>

          {/* ── AI Model ── */}
          <section className="settings-group">
            <div className="settings-group-head">
              <span className="settings-group-icon"><IconSparkle /></span>
              <h4>AI Model</h4>
              <span className="settings-group-meta">Groq</span>
            </div>
            <div className="settings-card">
              <select
                className="ai-model-select"
                value={aiModel}
                onChange={(e) => onSelectModel(e.target.value)}
              >
                {aiModels.map((m) => (
                  <option key={m.id} value={m.id}>{m.label}</option>
                ))}
              </select>
              <div className="ai-status-row">
                <span className={`ai-dot ai-dot-${aiReachable === null ? 'checking' : aiReachable ? 'ok' : 'down'}`} />
                <span className="ai-status-text">
                  {aiReachable === null ? 'Checking AI proxy…' : aiReachable ? 'AI proxy connected' : 'AI proxy unreachable'}
                </span>
              </div>
              {aiReachable === false && aiError && (
                <div className="llm-error">{aiError}</div>
              )}
            </div>
          </section>

          {/* ── Audit Log ── */}
          <section className="settings-group">
            <div className="settings-group-head">
              <span className="settings-group-icon"><IconScroll /></span>
              <h4>Audit Log</h4>
              <span className="settings-group-meta">{auditLog.length} {auditLog.length === 1 ? 'entry' : 'entries'}</span>
            </div>
            <div className="settings-card">
              <div className="setting-row">
                <div className="setting-row-text">
                  <div className="setting-row-label">Action history</div>
                  <div className="setting-row-desc">Every scan, probe and payload run, timestamped. Export as JSON.</div>
                </div>
                <button onClick={exportAuditLog} className="btn-small" disabled={!auditLog.length}>Export</button>
              </div>
            </div>
          </section>
        </div>
        );
      })()}

      {chains && (
        <div className="modal-overlay">
          <div className="modal report-modal">
            <div className="checklist-head">
              <h3>Proposed Chains <span className="muted">· {chains.chains.length}</span></h3>
              <button className="link-btn" onClick={() => setChains(null)}>Close</button>
            </div>
            <p className="checklist-sub">
              AI-proposed exploit chains across your findings. Every step is grounded in a real, in-scope finding — but these are hypotheses. Verify before reporting; nothing here runs.
            </p>
            <div className="find-list">
              {chains.chains.map((c) => (
                <div key={c.id} className={`find-card sev-${c.severity}`}>
                  <div className="find-card-top">
                    <span className={`find-sevtag sev-${c.severity}`}>{c.severity}</span>
                    <strong className="find-card-title">{c.title}</strong>
                  </div>
                  <div className="find-card-meta">
                    <span className="find-type">{c.steps.map((s) => s.type).join(' → ')}</span>
                    {c.aiCvss && <span className="find-conf" title="AI-proposed CVSS — unverified">{c.aiCvss}</span>}
                  </div>
                  {c.rationale && <div className="muted" style={{ fontSize: 11, lineHeight: 1.4, marginTop: 4 }}>{c.rationale}</div>}
                  <div className="muted" style={{ fontSize: 10, marginTop: 4 }}>AI-proposed · verify before reporting</div>
                </div>
              ))}
            </div>
            <div className="report-foot muted">
              Hypotheses only — confirm each chain yourself before reporting.
            </div>
          </div>
        </div>
      )}

      {escalation && (
        <div className="modal-overlay">
          <div className="modal report-modal">
            <div className="checklist-head">
              <h3>⚡ Escalate <span className="muted" style={{ fontSize: 12 }}>· {escalation.finding.title}</span></h3>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <button className="link-btn" disabled={escalationBusy || !(escalation.steps || []).some(isSafeStep)} onClick={runSafeSteps}>Run safe steps</button>
                <button className="link-btn" onClick={() => setEscalation(null)}>Close</button>
              </div>
            </div>
            <p className="checklist-sub">
              AI-proposed next tests, validated against the allowlist &amp; your scope. Nothing runs until you click it;
              active steps still honor dry-run &amp; confirmation.
            </p>
            <div className="muted" style={{ fontSize: 11, marginBottom: 6 }}>
              depth {escalation.depth || 0} · action budget {remainingBudget(escBudgetUsed)}/{DEFAULT_ESCALATION_BUDGET} left this session
            </div>
            {escalation.loading ? (
              <div className="hint">Planning…</div>
            ) : (escalation.steps || []).length === 0 ? (
              <div className="hint">No actionable steps were proposed for this finding.</div>
            ) : (
              <div className="escalation-steps">
                {escalation.steps.map((s, i) => (
                  <div key={s.id || i} className={`agent-finding ${s.type === 'manual' ? '' : `sev-${s.risk === 'active' ? 'high' : 'low'}`}`}>
                    <span className="sev-badge">{s.type === 'manual' ? 'manual' : s.risk}</span>{' '}
                    <strong>{s.type}</strong>
                    {s.target && <code style={{ fontSize: 10, marginLeft: 6 }}>{s.target}{s.param ? ` (${s.param})` : ''}</code>}
                    {s.payloadFamily && <code style={{ fontSize: 10, marginLeft: 6 }}>{s.payloadFamily}</code>}
                    {s.tool && <code style={{ fontSize: 10, marginLeft: 6 }}>{s.tool}</code>}
                    {s.type !== 'manual' && (
                      <button className="btn-small" style={{ float: 'right' }} onClick={() => executeStep(s)}>Run</button>
                    )}
                    <div className="muted" style={{ fontSize: 11, marginTop: 2 }}>{s.rationale || s.note}</div>
                    {s.expectedSignal && <div className="muted" style={{ fontSize: 10 }}>expect: {s.expectedSignal}</div>}
                    {s.reason && <div className="muted" style={{ fontSize: 10 }}>⚠ downgraded: {s.reason}</div>}
                  </div>
                ))}
                {(escalation.rejected || []).length > 0 && (
                  <div className="muted" style={{ fontSize: 10, marginTop: 6 }}>
                    {escalation.rejected.length} step(s) rejected (over cap).
                  </div>
                )}
              </div>
            )}
            <div className="report-foot muted">
              Proposals only — you decide what runs. Confirm findings yourself before reporting.
            </div>
          </div>
        </div>
      )}

      {reportDraft && (() => {
        const upd = (k, v) => setReportDraft((prev) => ({ ...prev, [k]: v }));
        const md = buildReport(reportDraft, reportDraft.platform);
        const copyMd = async () => {
          try { await navigator.clipboard.writeText(md); toast.success('Report copied'); }
          catch (_) { toast.error('Copy failed'); }
        };
        const downloadMd = () => {
          const blob = new Blob([md], { type: 'text/markdown' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `report_${(reportDraft.target || 'target').replace(/[^\w.-]/g, '_')}_${Date.now()}.md`;
          a.click();
        };
        return (
          <div className="modal-overlay">
            <div className="modal report-modal">
              <div className="checklist-head">
                <h3>Draft Report</h3>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <button
                    className="link-btn"
                    disabled={!!aiReportBusy}
                    title="Draft summary/steps/impact/remediation from the evidence with AI"
                    onClick={async () => {
                      const evidence = [reportDraft.title, reportDraft.ref, reportDraft.evidence, reportDraft.summary].filter(Boolean).join('\n');
                      if (!evidence.trim()) { toast.info('Add a title or evidence first.'); return; }
                      setAiReportBusy('draft');
                      try {
                        const d = await ai.draftFinding(evidence, aiModel);
                        setReportDraft((prev) => ({
                          ...prev,
                          summary: d.summary || prev.summary,
                          steps: (d.steps && d.steps.length) ? d.steps.join('\n') : prev.steps,
                          impact: d.impact || prev.impact,
                          remediation: d.remediation || prev.remediation,
                        }));
                        toast.success('AI drafted the report sections — review before submitting.');
                      } catch (e) {
                        toast.error('AI draft failed: ' + (e?.message || 'unknown'));
                      } finally { setAiReportBusy(''); }
                    }}
                  >{aiReportBusy === 'draft' ? '✨ Drafting…' : '✨ AI draft'}</button>
                  <button
                    className="link-btn"
                    disabled={!!aiReportBusy}
                    title="Ask AI to assess whether the evidence indicates a real vulnerability"
                    onClick={async () => {
                      if (!reportDraft.evidence.trim()) { toast.info('Paste request/response evidence first.'); return; }
                      setAiReportBusy('triage');
                      try {
                        const v = await ai.classifyResponse(
                          { request: reportDraft.title, response: reportDraft.evidence, context: { type: reportDraft.ref, target: reportDraft.target } },
                          aiModel
                        );
                        if (SEVERITIES.includes(v.severity)) upd('severity', v.severity);
                        toast[v.likelyVuln ? 'success' : 'info'](`AI: ${v.likelyVuln ? 'likely vulnerable' : 'weak/none'} · ${v.severity}${v.reason ? ' — ' + v.reason : ''}`);
                      } catch (e) {
                        toast.error('AI triage failed: ' + (e?.message || 'unknown'));
                      } finally { setAiReportBusy(''); }
                    }}
                  >{aiReportBusy === 'triage' ? '🔎 Assessing…' : '🔎 AI triage'}</button>
                  <button className="link-btn" onClick={() => setReportDraft(null)}>Close</button>
                </div>
              </div>
              <div className="report-grid">
                <div className="report-form">
                  {reportDraft.rationale && (
                    <div className="report-why muted" style={{ fontSize: 11, marginBottom: 6, lineHeight: 1.4 }}>
                      <strong>Why this confidence:</strong> {reportDraft.rationale}
                    </div>
                  )}
                  <label>Platform
                    <select value={reportDraft.platform} onChange={(e) => upd('platform', e.target.value)}>
                      {REPORT_PLATFORMS.map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
                    </select>
                  </label>
                  <label>Severity
                    <select value={reportDraft.severity} onChange={(e) => upd('severity', e.target.value)}>
                      {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
                    </select>
                  </label>
                  <label>Title<input value={reportDraft.title} onChange={(e) => upd('title', e.target.value)} /></label>
                  <label>Target<input value={reportDraft.target} onChange={(e) => upd('target', e.target.value)} /></label>
                  <label>Program<input value={reportDraft.program} onChange={(e) => upd('program', e.target.value)} placeholder="e.g. Example (H1)" /></label>
                  <label>Summary<textarea rows={2} value={reportDraft.summary} onChange={(e) => upd('summary', e.target.value)} /></label>
                  <label>Steps (one per line)<textarea rows={3} value={reportDraft.steps} onChange={(e) => upd('steps', e.target.value)} /></label>
                  <label>Impact<textarea rows={2} value={reportDraft.impact} onChange={(e) => upd('impact', e.target.value)} /></label>
                  <label>Evidence (request/response)<textarea rows={3} value={reportDraft.evidence} onChange={(e) => upd('evidence', e.target.value)} spellCheck={false} /></label>
                </div>
                <div className="report-preview">
                  <div className="report-preview-head">
                    <span className="muted">Preview ({reportDraft.ref || 'no ref'})</span>
                    <div style={{ display: 'flex', gap: 6 }}>
                      <button className="btn-small" onClick={copyMd}>Copy</button>
                      <button className="btn-small" onClick={downloadMd}>Download</button>
                    </div>
                  </div>
                  <pre className="report-md">{md}</pre>
                </div>
              </div>
              <div className="report-foot muted">
                Draft only — verify the finding and its impact yourself before submitting. Never submit auto-generated reports.
              </div>
            </div>
          </div>
        );
      })()}

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
