import React, { useState, useEffect } from 'react';
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
  const [reportDraft, setReportDraft] = useState(null); // report-builder modal state
  const [aiReportBusy, setAiReportBusy] = useState(''); // '' | 'draft' | 'triage'
  const [escalation, setEscalation] = useState(null); // { finding, steps, rejected, depth } — AI escalation plan
  const [escalationBusy, setEscalationBusy] = useState(false);
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
  const [activeTab, setActiveTab] = useState('Scan'); // 'Scan' | 'Payloads' | 'Recon' | 'History' | 'Settings'
  const [payloadHistory, setPayloadHistory] = useState([]);
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
    setReportDraft({
      platform: 'hackerone',
      title: f.title || 'Finding',
      target: f.host || currentHost,
      program: '',
      ref: f.ref || '',
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
    try { await navigator.clipboard.writeText(text); } catch (e) { toast.error('Copy failed'); }
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
            <span className="header-icon"><IconShield /></span>
            SecTest Pro
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
          <span className="header-icon"><IconShield /></span>
          SecTest Pro
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
              <button onClick={runConfirmReflection} className="btn-secondary" disabled={reflectionBusy || !isHostAllowed(currentUrl)} title="Inject a benign marker and report where it reflects (DOM-only, reversible)">
                {reflectionBusy ? 'Checking…' : 'Confirm Reflection'}
              </button>
            </div>
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

            <label title="Generate a payload with AI (Groq)">
              <input
                type="radio"
                name="payloadSource"
                value="llm"
                checked={payloadSource === 'llm'}
                onChange={(e) => setPayloadSource(e.target.value)}
              />
              AI suggestion
            </label>
            <div className="llm-row">
              <button className="btn-small" onClick={fetchLlmSuggestion} disabled={llmLoading}>
                {llmLoading ? '⏳ Generating…' : '✨ Generate with AI'}
              </button>
              <textarea
                rows={2}
                placeholder="Generated payload will appear here"
                value={llmPayload}
                readOnly
              />
            </div>
            {llmExplanation && (
              <div className="llm-explanation">
                <strong>Why:</strong> {llmExplanation}
              </div>
            )}
            {aiReachable === false && (
              <div className="llm-hint">
                AI proxy not reachable. Check that the Edge Function is deployed and you're logged in.
                {aiError && <div className="llm-error">Last error: {aiError}</div>}
              </div>
            )}
          </div>
        </div>
      )}

      {activeTab === 'Recon' && (
        <div className="recon-panel">
          {(() => {
            const inv = (currentHost && inventory[currentHost]) || emptyInventory();
            const sum = summarizeInventory(inv);
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
                  {[
                    ['Pages', sum.pages],
                    ['Endpoints', sum.endpoints],
                    ['Params', sum.params],
                    ['Scripts', sum.scripts],
                    ['Forms', sum.forms],
                    ['Cookies', sum.cookieNames],
                    ['Secrets', sum.secrets],
                    ['Sinks', sum.sinks],
                  ].map(([k, v]) => (
                    <div key={k} className="inv-stat"><span className="inv-stat-num">{v}</span><span className="inv-stat-label">{k}</span></div>
                  ))}
                </div>
                {sum.endpoints > 0 && (
                  <details className="inv-details">
                    <summary>Endpoints ({sum.endpoints})</summary>
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
                    <summary>Params ({sum.params})</summary>
                    <div className="inv-list">{inv.params.slice(0, 300).map((p, i) => <span key={i} className="tag">{p}</span>)}</div>
                  </details>
                )}
                {sum.scripts > 0 && (
                  <details className="inv-details">
                    <summary>Scripts ({sum.scripts})</summary>
                    <div className="inv-list">{inv.scripts.slice(0, 200).map((s, i) => <div key={i} className="inv-list-item"><code>{s}</code></div>)}</div>
                  </details>
                )}
                {sum.secrets > 0 && (
                  <details className="inv-details" open>
                    <summary>⚠️ Secrets ({sum.secrets})</summary>
                    <div className="inv-list">
                      {inv.secrets.slice(0, 200).map((s, i) => (
                        <div key={i} className="jswatch-secret">⚠️ {s.type}: <code>{s.preview}</code></div>
                      ))}
                    </div>
                  </details>
                )}
                {sum.sinks > 0 && (
                  <details className="inv-details">
                    <summary>DOM-XSS sinks ({sum.sinks})</summary>
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
              <div className="hint">🔒 DRY RUN — would fetch {jsScanResult.wouldFetch.length} file(s). Disable Dry Run in Config to diff.</div>
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
                            <div key={k} className="jswatch-secret">⚠️ {s.type}: <code>{s.preview}</code></div>
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
                      🔒 DRY RUN on <code>{differentialResult.param}</code> — would GET {differentialResult.wouldFetch?.length} variant(s). Disable Dry Run to probe.
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
                  <h4>⚠️ Secrets in inline scripts ({recon.secrets.length})</h4>
                  {recon.secrets.map((s, i) => (
                    <div key={i} className="jswatch-secret">⚠️ {s.type}: <code>{s.preview}</code></div>
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
                      <div key={i} className="muted">🔒 would fetch: {u}</div>
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
        const sorted = sortFindings(dedupeFindings(all, { crossHost: findingsCrossHost }));
        const sum = summarizeFindings(sorted);
        return (
          <div className="recon-panel">
            <div className="checklist-head">
              <h3>Findings {currentHost && !findingsCrossHost && <span className="muted">· {currentHost}</span>}</h3>
              <div style={{ display: 'flex', gap: 8 }}>
                <button className="link-btn" onClick={refreshFindings}>Refresh</button>
                <button className="link-btn" onClick={() => clearFindingsForHost(currentHost)} disabled={!currentHost || !findings[currentHost]}>Clear host</button>
              </div>
            </div>
            <p className="checklist-sub">
              Unified from header analysis, DOM-XSS taint &amp; response oracles. Confidence reflects evidence strength — confirm before submitting.
            </p>
            <label className="muted" style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, margin: '2px 0 8px' }}>
              <input type="checkbox" checked={findingsCrossHost} onChange={(e) => setFindingsCrossHost(e.target.checked)} />
              Merge across all hosts (program-wide dedup)
            </label>
            <div className="inv-stats">
              {[['Critical', sum.critical], ['High', sum.high], ['Medium', sum.medium], ['Low', sum.low], ['Info', sum.informational]].map(([k, v]) => (
                <div key={k} className="inv-stat"><span className="inv-stat-num">{v}</span><span className="inv-stat-label">{k}</span></div>
              ))}
            </div>
            {sorted.length === 0 ? (
              <div className="hint">No findings yet. Run Deep JS Scan, browse in-scope pages (headers), or Diff an endpoint.</div>
            ) : (
              sorted.map((f, i) => (
                <div key={i} className={`agent-finding sev-${f.severity}`}>
                  <span className="sev-badge">{f.severity}</span> <strong>{f.title}</strong>
                  {typeof f.confidence === 'number' && <span className="muted" style={{ fontSize: 10 }}> · conf {f.confidence}</span>}
                  {findingsCrossHost && f.host && <span className="muted" style={{ fontSize: 10 }}> · {f.host}</span>}
                  <span style={{ float: 'right', display: 'flex', gap: 4 }}>
                    <button
                      className="btn-small"
                      disabled={escalationBusy || !canEscalate({ depth: Number(f.depth) || 0, budgetUsed: escBudgetUsed })}
                      onClick={() => runEscalate(f)}
                      title={canEscalate({ depth: Number(f.depth) || 0, budgetUsed: escBudgetUsed })
                        ? 'Ask AI for next steps to escalate this finding'
                        : 'Escalation limit reached (max depth or session budget)'}
                    >⚡ Escalate{(Number(f.depth) || 0) > 0 ? ` (d${f.depth})` : ''}</button>
                    <button className="btn-small" onClick={() => draftFromFinding(f)}>Draft report</button>
                  </span>
                  <div className="muted" style={{ fontSize: 10 }}>{f.type} · {f.ref} · {f.evidence}</div>
                </div>
              ))
            )}
          </div>
        );
      })()}

      {activeTab === 'Checklist' && (() => {
        const summary = summarizeProgress(checklistProgress);
        const STATE_META = {
          todo:    { label: 'To do',   short: '·' },
          testing: { label: 'Testing', short: '◐' },
          pass:    { label: 'Pass',    short: '✓' },
          finding: { label: 'Finding', short: '★' },
          na:      { label: 'N/A',     short: '–' },
        };
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

            <div className="checklist-progress">
              <div className="checklist-bar">
                <div className="checklist-bar-fill" style={{ width: `${summary.percentComplete}%` }} />
              </div>
              <div className="checklist-progress-meta">
                <span>{summary.percentComplete}% touched</span>
                <span className="muted">
                  {STATE_META.finding.short} {summary.counts.finding} · {STATE_META.pass.short} {summary.counts.pass} · {STATE_META.testing.short} {summary.counts.testing} · {summary.counts.todo} left
                </span>
              </div>
            </div>

            {CHECKLIST.map((cat) => {
              const open = openCategories.has(cat.id);
              const done = cat.items.filter((it) => (checklistProgress[it.id] || 'todo') !== 'todo').length;
              return (
                <div key={cat.id} className="checklist-cat">
                  <button className="checklist-cat-head" onClick={() => toggleCategory(cat.id)}>
                    <span className="checklist-cat-caret">{open ? '▾' : '▸'}</span>
                    <span className="checklist-cat-name">{cat.name}</span>
                    <span className="checklist-cat-count muted">{done}/{cat.items.length}</span>
                  </button>
                  {open && (
                    <div className="checklist-items">
                      {cat.items.map((item) => {
                        const state = checklistProgress[item.id] || 'todo';
                        return (
                          <div key={item.id} className={`checklist-item checklist-item-${state}`}>
                            <div className="checklist-item-top">
                              <span className="checklist-ref">{item.ref}</span>
                              <span className="checklist-title">{item.title}</span>
                              {item.payloadKey && (
                                <button
                                  className="btn-small checklist-payload"
                                  title="Load preset payloads for this test"
                                  onClick={() => jumpToPayload(item.payloadKey)}
                                >
                                  payloads →
                                </button>
                              )}
                              <button
                                className="btn-small checklist-report"
                                title="Draft a report for this finding"
                                onClick={() => openReportDraft(item, cat.name)}
                              >
                                report →
                              </button>
                            </div>
                            <div className="checklist-states">
                              {CHECKLIST_STATES.map((s) => (
                                <button
                                  key={s}
                                  className={`checklist-state-btn${state === s ? ' active' : ''} checklist-state-${s}`}
                                  onClick={() => setChecklistItemState(item.id, s)}
                                  title={STATE_META[s].label}
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
        return (
          <div className="programs-panel">
            <h3><IconPrograms />Programs &amp; Payouts</h3>
            <div className="inv-stats">
              <div className="inv-stat"><span className="inv-stat-num">${overall.earned.toLocaleString()}</span><span className="inv-stat-label">Earned</span></div>
              <div className="inv-stat"><span className="inv-stat-num">{overall.paidCount}</span><span className="inv-stat-label">Paid</span></div>
              <div className="inv-stat"><span className="inv-stat-num">{overall.pipeline}</span><span className="inv-stat-label">In pipeline</span></div>
              <div className="inv-stat"><span className="inv-stat-num">{overall.total}</span><span className="inv-stat-label">Total</span></div>
            </div>

            <div className="prog-form">
              <h4>Add program</h4>
              <div className="prog-form-row">
                <input placeholder="Program name" value={progForm.name} onChange={(e) => setProgForm({ ...progForm, name: e.target.value })} />
                <select value={progForm.platform} onChange={(e) => setProgForm({ ...progForm, platform: e.target.value })}>
                  {PLATFORMS.map((p) => <option key={p} value={p}>{p}</option>)}
                </select>
              </div>
              <div className="prog-form-row">
                <input placeholder="Program URL (optional)" value={progForm.url} onChange={(e) => setProgForm({ ...progForm, url: e.target.value })} />
                <button className="btn-small" onClick={addProgram}>Add</button>
              </div>
            </div>

            {programs.length > 0 && (
              <div className="prog-form">
                <h4>Log a submission</h4>
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
                  <input type="number" placeholder="$ bounty" value={subForm.bounty} onChange={(e) => setSubForm({ ...subForm, bounty: e.target.value })} style={{ width: 80 }} />
                  <button className="btn-small" onClick={addSubmission}>Log</button>
                </div>
              </div>
            )}

            {rolled.length > 0 && (
              <div className="prog-list">
                <h4>Programs ({rolled.length})</h4>
                {rolled.map((p) => (
                  <div key={p.id} className="prog-item">
                    <div className="prog-item-main">
                      <strong>{p.name}</strong> <span className="tag">{p.platform}</span>
                      <div className="muted" style={{ fontSize: 11 }}>
                        {p.submissionCount} submission(s) · ${p.summary.earned.toLocaleString()} earned · {p.summary.pipeline} open
                      </div>
                    </div>
                    <button className="btn-remove" onClick={() => deleteProgram(p.id)}>×</button>
                  </div>
                ))}
              </div>
            )}

            {submissions.length > 0 && (
              <div className="prog-list">
                <h4>Submissions ({submissions.length})</h4>
                {submissions.map((s) => (
                  <div key={s.id} className="prog-item">
                    <div className="prog-item-main">
                      <strong>{s.title}</strong>
                      <div className="muted" style={{ fontSize: 11 }}>
                        {progName(s.programId)} · {s.severity}{s.bounty ? ` · $${s.bounty}` : ''}
                      </div>
                    </div>
                    <select value={s.state} onChange={(e) => setSubmissionState(s.id, e.target.value)} className="sub-state">
                      {SUBMISSION_STATES.map((st) => <option key={st} value={st}>{st}</option>)}
                    </select>
                    <button className="btn-remove" onClick={() => deleteSubmission(s.id)}>×</button>
                  </div>
                ))}
              </div>
            )}
            {programs.length === 0 && <div className="hint">Add a program to start tracking submissions and payouts.</div>}
          </div>
        );
      })()}

      {activeTab === 'AI' && (
        <div className="ai-chat-panel">
          <div className="ai-chat-head">
            <h3><IconAI />AI Assistant</h3>
            <button
              className="link-btn"
              onClick={() => setChatMessages([])}
              disabled={chatBusy || chatMessages.length === 0}
            >
              Clear
            </button>
          </div>
          <p className="ai-chat-sub">
            Paste a payload to get it explained, critiqued, and improved — or ask anything about testing this page.
          </p>

          <div className="ai-chat-log">
            {chatMessages.length === 0 && (
              <div className="ai-chat-empty">
                <p>Try:</p>
                <button className="ai-chip" onClick={() => sendChat("Explain this payload and suggest a stronger one: <script>alert(1)</script>")}>
                  Analyze a sample XSS payload
                </button>
                <button className="ai-chip" onClick={() => sendChat("Give me an effective SQL injection payload for a login form and explain it.")}>
                  Suggest a SQLi payload
                </button>
              </div>
            )}
            {chatMessages.map((m, i) => (
              <div key={i} className={`ai-msg ai-msg-${m.role}`}>
                <div className="ai-msg-role">{m.role === 'user' ? 'You' : 'AI'}</div>
                <div className="ai-msg-body">{m.content}</div>
              </div>
            ))}
            {chatBusy && <div className="ai-msg ai-msg-assistant"><div className="ai-msg-role">AI</div><div className="ai-msg-body">⏳ Thinking…</div></div>}
          </div>

          <div className="ai-chat-input">
            <textarea
              rows={3}
              placeholder="Paste a payload or ask a question…  (Enter to send, Shift+Enter for newline)"
              value={chatInput}
              onChange={(e) => setChatInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault();
                  sendChat();
                }
              }}
              disabled={chatBusy}
            />
            <button className="btn-primary" onClick={() => sendChat()} disabled={chatBusy || !chatInput.trim()}>
              {chatBusy ? '…' : 'Send'}
            </button>
          </div>
          {aiReachable === false && (
            <div className="llm-hint">AI proxy not reachable. Check that the Edge Function is deployed and you're logged in.</div>
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
            <h4>Program Scope</h4>
            <p className="scope-help">
              One host pattern per line. <code>*.example.com</code> = apex + subdomains,
              <code>example.com</code> = exact host, <code>*</code> = everything.
              Out-of-scope always wins. Enforced before any scan, probe or capture.
            </p>
            <label className="scope-label">In scope</label>
            <textarea
              className="scope-textarea"
              rows={4}
              value={scopeInText}
              onChange={(e) => setScopeInText(e.target.value)}
              placeholder={'*.example.com\napi.example.com'}
              spellCheck={false}
            />
            <label className="scope-label">Out of scope</label>
            <textarea
              className="scope-textarea"
              rows={3}
              value={scopeOutText}
              onChange={(e) => setScopeOutText(e.target.value)}
              placeholder={'admin.example.com\n*.dev.example.com'}
              spellCheck={false}
            />
            <button onClick={saveScope} className="btn-small">Save Scope</button>
            <div className="scope-current muted">
              {currentHost
                ? (() => {
                    const s = scopeStatus(currentUrl);
                    return <>Current host <code>{currentHost}</code>: {s.allowed ? '✅ in scope' : `⛔ ${s.reason.replace(/_/g, ' ')}`}</>;
                  })()
                : 'Open an http(s) page to see its scope status.'}
            </div>
          </div>

          <div className="setting-item">
            <label>
              <input type="checkbox" checked={passiveCapture} onChange={togglePassiveCapture} />
              Passive capture (record endpoints/params/JS as you browse in-scope targets)
            </label>
          </div>

          <div className="setting-item">
            <h4>Notifications</h4>
            <label>
              <input
                type="checkbox"
                checked={notifyConfig.enabled}
                onChange={(e) => saveNotifyConfig({ ...notifyConfig, enabled: e.target.checked })}
              />
              Alert on new JS endpoints/secrets (deltas only)
            </label>
            <div className="allowlist-input" style={{ marginTop: 6 }}>
              <select
                value={notifyConfig.webhookPlatform}
                onChange={(e) => saveNotifyConfig({ ...notifyConfig, webhookPlatform: e.target.value })}
              >
                {WEBHOOK_PLATFORMS.map((p) => <option key={p} value={p}>{p}</option>)}
              </select>
              <input
                type="text"
                placeholder="Optional webhook URL (Discord/Slack/Telegram)"
                value={notifyConfig.webhookUrl}
                onChange={(e) => saveNotifyConfig({ ...notifyConfig, webhookUrl: e.target.value })}
              />
            </div>
            <div className="scope-help">Leave the webhook blank for local Chrome notifications only.</div>
          </div>

          <div className="setting-item">
            <h4>Background JS Monitor</h4>
            <label>
              <input
                type="checkbox"
                checked={jsMonitor.enabled}
                onChange={(e) => saveJsMonitor({ ...jsMonitor, enabled: e.target.checked })}
              />
              Auto re-scan tracked hosts on a schedule
            </label>
            <div className="allowlist-input" style={{ marginTop: 6 }}>
              <input
                type="number"
                min={15}
                value={jsMonitor.intervalMinutes}
                onChange={(e) => saveJsMonitor({ ...jsMonitor, intervalMinutes: Math.max(15, Number(e.target.value) || 360) })}
                style={{ width: 90 }}
              />
              <span className="muted" style={{ fontSize: 11 }}>minutes between scans (min 15). Paused while Dry Run is on.</span>
            </div>
          </div>

          <div className="setting-item">
            <h4>Companion Agent (Phase 3)</h4>
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
            <div className="allowlist-input" style={{ marginTop: 8 }}>
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
            {agentHealthInfo && agentHealthInfo.ok === false && (
              <div className="hint">Unreachable. Start it with <code>docker compose up</code> in <code>agent/</code>.</div>
            )}
          </div>

          <div className="setting-item">
            <h4>Audit Log ({auditLog.length} entries)</h4>
            <button onClick={exportAuditLog} className="btn-small">
              Export Log
            </button>
          </div>

          <div className="setting-item">
            <h4>AI Model (Groq)</h4>
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
