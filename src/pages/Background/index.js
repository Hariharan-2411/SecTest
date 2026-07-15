console.log('SecTest Pro - Background Service Worker');

import {
  buildReconFileUrls,
  normalizeEndpoint,
} from '../../utils/reconHelpers';
import { evaluateScope, scopeFromAllowlist } from '../../utils/scope';
import { mergeObservation, extractParamsFromUrls } from '../../utils/inventory';
import {
  isApiEvent,
  mergeApiEvent,
  templatizePath,
  apiSpecCandidates,
  parseOpenApi,
  mergeSpecEndpoints,
  buildApiFindings,
} from '../../utils/apisurface';
import { analyzeHeaders, mergeHeaderFindings } from '../../utils/headers';
import { upsertFindings as upsertFindingsList } from '../../utils/findings';
import {
  buildVariantUrl,
  firstParam,
  paramValue,
  classifyDifferential,
  classifyTiming,
} from '../../utils/oracle';
import { makeSnapshot, diffSnapshots, isInterestingDiff, summarizeDiff } from '../../utils/jsdiff';
import { formatJsAlertTitle, formatJsAlertBody, buildWebhookPayload, shouldNotify } from '../../utils/notify';

const storageGet = (keys) =>
  new Promise((resolve) => chrome.storage.local.get(keys, resolve));
const storageSet = (obj) =>
  new Promise((resolve) => chrome.storage.local.set(obj, resolve));

// Rate limiting. The MV3 service worker is ephemeral — it's torn down and
// respawned between messages — so an in-memory counter would silently reset and
// the limit would not hold. We persist the timestamp ring to chrome.storage so
// the window survives worker suspension.
const rateLimiter = {
  maxActionsPerMinute: 20,

  async _recent() {
    const r = await storageGet(['rateActions']);
    const cutoff = Date.now() - 60000;
    return (r.rateActions || []).filter((t) => t > cutoff);
  },

  async canPerformAction() {
    const recent = await this._recent();
    if (recent.length >= this.maxActionsPerMinute) return false;
    recent.push(Date.now());
    await storageSet({ rateActions: recent });
    return true;
  },

  async getRemainingActions() {
    const recent = await this._recent();
    return this.maxActionsPerMinute - recent.length;
  },
};

// NOTE: a previous `payloadValidator.isSafe` helper was removed — it defaulted
// to "sanctioned" for every host (its list contained '*'), so it always
// returned safe:true and provided no real protection (false assurance). The
// actual guardrails are scope enforcement (evaluateScope), dry-run, rate limits,
// and human confirmation. Its unused `validatePayload` message handler was
// removed with it.

// --- Settings & audit helpers (Promise-wrapped chrome.storage) -------------

function getSettings() {
  return new Promise((resolve) => {
    chrome.storage.local.get(
      ['allowlist', 'scope', 'passiveCapture', 'dryRunMode', 'auditLog', 'notifyConfig', 'jsMonitor'],
      (r) => {
        // Prefer the structured scope; migrate from the legacy allowlist if absent.
        const scope = r.scope && Array.isArray(r.scope.inScope)
          ? r.scope
          : scopeFromAllowlist(r.allowlist || ['*']);
        resolve({
          scope,
          passiveCapture: r.passiveCapture !== false, // default true
          dryRunMode: r.dryRunMode !== false, // default true
          auditLog: r.auditLog || [],
          notifyConfig: r.notifyConfig || { enabled: true, webhookUrl: '', webhookPlatform: 'discord' },
          jsMonitor: r.jsMonitor || { enabled: false, intervalMinutes: 360 },
        });
      }
    );
  });
}

// Merge a passive page observation into the per-host inventory (scope-gated).
async function recordObservation(pageUrl, observation) {
  const { scope, passiveCapture } = await getSettings();
  if (!passiveCapture) return { success: false, reason: 'capture_disabled' };
  const { allowed, host } = evaluateScope(pageUrl, scope);
  if (!allowed) return { success: false, reason: 'out_of_scope', host };

  return new Promise((resolve) => {
    chrome.storage.local.get(['inventory'], (r) => {
      const store = r.inventory || {};
      store[host] = mergeObservation(store[host], { ...observation, pageUrl });
      chrome.storage.local.set({ inventory: store }, () =>
        resolve({ success: true, host })
      );
    });
  });
}

// --- Passive security-header analysis (webRequest, observe-only) -----------
//
// Reads response headers of traffic the user ALREADY generated on in-scope
// hosts and records header/cookie misconfigurations. It never blocks, modifies,
// or issues requests — purely observational, scope-gated, and deduped per host.

// In-memory throttle so we analyze each (host, path, type) once per worker life.
// The MV3 worker is ephemeral, so this naturally resets; storage dedup (by
// finding id) keeps the persisted set stable regardless.
const seenHeaderKeys = new Set();

async function recordHeaderFindings(host, url, findings) {
  const r = await storageGet(['headerFindings']);
  const store = r.headerFindings || {};
  const prev = (store[host] && store[host].findings) || [];
  store[host] = {
    url,
    checkedAt: new Date().toISOString(),
    findings: mergeHeaderFindings(prev, findings),
  };
  await storageSet({ headerFindings: store });
  // Also fold into the unified findings store (Phase E).
  await persistFindingsGrouped(findings.map((f) => ({ ...f, host, type: 'header', source: 'headers' })));
}

// --- Unified findings store (Phase E) --------------------------------------
// One place all sources (headers, DOM-XSS taint, oracles) write to. Keyed by
// host, deduped by finding id, capped per host. Pure merge logic in findings.js.

async function persistFindingsGrouped(list) {
  const items = Array.isArray(list) ? list.filter(Boolean) : [];
  if (!items.length) return { success: true, count: 0 };
  const r = await storageGet(['findings']);
  const store = r.findings || {};
  const byHost = {};
  for (const f of items) {
    const h = f.host || '';
    (byHost[h] = byHost[h] || []).push(f);
  }
  for (const h of Object.keys(byHost)) {
    store[h] = upsertFindingsList(store[h], byHost[h]).slice(-500);
  }
  await storageSet({ findings: store });
  return { success: true, count: items.length };
}

async function handleHeadersReceived(details) {
  try {
    const { scope, passiveCapture } = await getSettings();
    if (!passiveCapture) return;
    const ev = evaluateScope(details.url, scope);
    if (!ev.allowed) return;

    let path = '';
    try { path = new URL(details.url).pathname; } catch (_) {}
    const key = `${ev.host}|${path}|${details.type}`;
    if (seenHeaderKeys.has(key)) return;
    seenHeaderKeys.add(key);
    if (seenHeaderKeys.size > 2000) seenHeaderKeys.clear(); // bound memory

    const findings = analyzeHeaders({
      url: details.url,
      type: details.type,
      statusLine: details.statusLine,
      headers: details.responseHeaders || [],
    });
    if (findings.length) await recordHeaderFindings(ev.host, details.url, findings);
  } catch (_) {
    // Observation must never throw into the webRequest pipeline.
  }
}

// --- Passive API surface discovery (webRequest, observe-only) --------------
//
// Folds the URL/method/auth of XHR & fetch traffic the user ALREADY generated
// on in-scope hosts into a per-host endpoint inventory (routes templated so
// /users/123 and /users/456 collapse to one). Never blocks, modifies, or issues
// a request. Writes are throttled per (host, method, route, params) for this
// worker life so a chatty SPA doesn't hammer storage.
const seenApiKeys = new Set();

async function recordApiRequest(details) {
  try {
    const event = {
      url: details.url,
      method: details.method,
      type: details.type,
      requestHeaders: details.requestHeaders || [],
    };
    if (!isApiEvent(event)) return;
    const { scope, passiveCapture } = await getSettings();
    if (!passiveCapture) return;
    const ev = evaluateScope(details.url, scope);
    if (!ev.allowed) return;

    const path = templatizePath(details.url);
    if (!path) return;
    const params = extractParamsFromUrls([details.url]).sort().join(',');
    const key = `${ev.host}|${(details.method || 'GET').toUpperCase()} ${path}|${params}`;
    if (seenApiKeys.has(key)) return; // route+params already recorded this life
    seenApiKeys.add(key);
    if (seenApiKeys.size > 4000) seenApiKeys.clear(); // bound memory

    const r = await storageGet(['apiInventory']);
    const store = r.apiInventory || {};
    store[ev.host] = mergeApiEvent(store[ev.host] || [], event);
    await storageSet({ apiInventory: store });
  } catch (_) {
    // Observation must never throw into the webRequest pipeline.
  }
}

// Read the API inventory for a page's in-scope host (for the Recon → API view).
async function getApiSurface(pageUrl) {
  const { scope } = await getSettings();
  const ev = evaluateScope(pageUrl, scope);
  if (!ev.allowed) return { success: false, reason: ev.reason, host: ev.host };
  const r = await storageGet(['apiInventory']);
  const inventory = (r.apiInventory || {})[ev.host] || [];
  return { success: true, host: ev.host, inventory };
}

// Persist an api-surface (and api-spec-exposed) finding into the unified store.
async function saveApiFindings(pageUrl, specUrl, specEndpoints) {
  const { scope } = await getSettings();
  const ev = evaluateScope(pageUrl, scope);
  if (!ev.allowed) return { success: false, reason: ev.reason, host: ev.host };
  const r = await storageGet(['apiInventory']);
  const inventory = (r.apiInventory || {})[ev.host] || [];
  const findings = buildApiFindings({
    host: ev.host,
    specUrl,
    specEndpoints,
    inventory,
  });
  await persistFindingsGrouped(findings);
  return { success: true, host: ev.host, saved: findings.length };
}

// Active, gated probe for a publicly readable OpenAPI/Swagger spec. Fetches the
// well-known spec paths (dry-run aware, scope-gated, rate-limited); on a hit it
// folds the parsed routes into the inventory and records an api-spec-exposed
// finding. Read-only GETs; no payloads.
async function probeApiSpec(pageUrl) {
  const { scope, dryRunMode } = await getSettings();
  const ev = evaluateScope(pageUrl, scope);
  if (!ev.allowed) return { success: false, reason: ev.reason, host: ev.host };
  const host = ev.host;
  const candidates = apiSpecCandidates(pageUrl);

  if (dryRunMode) {
    await appendAudit({ action: 'API_SPEC_PROBE', url: pageUrl, host, result: 'DRY_RUN', dryRun: true, wouldFetch: candidates });
    return { success: true, dryRun: true, wouldFetch: candidates, host };
  }

  for (const url of candidates) {
    if (!(await rateLimiter.canPerformAction())) {
      return { success: false, reason: 'rate_limited' };
    }
    const res = await fetchJsText(url); // full body; JSON.parse needs it whole
    if (!res.ok || !res.text) continue;
    let spec = null;
    try { spec = JSON.parse(res.text); } catch (_) { continue; }
    const endpoints = parseOpenApi(spec);
    if (!endpoints.length) continue;

    const invR = await storageGet(['apiInventory']);
    const invStore = invR.apiInventory || {};
    invStore[host] = mergeSpecEndpoints(invStore[host] || [], endpoints);
    await storageSet({ apiInventory: invStore });

    const findings = buildApiFindings({ host, specUrl: url, specEndpoints: endpoints, inventory: invStore[host] });
    await persistFindingsGrouped(findings);
    await appendAudit({ action: 'API_SPEC_PROBE', url: pageUrl, host, result: 'EXECUTED', dryRun: false, specUrl: url, endpoints: endpoints.length });
    return { success: true, dryRun: false, host, specUrl: url, endpoints, inventory: invStore[host] };
  }

  await appendAudit({ action: 'API_SPEC_PROBE', url: pageUrl, host, result: 'EXECUTED', dryRun: false, specUrl: null });
  return { success: true, dryRun: false, host, specUrl: null, endpoints: [] };
}

function appendAudit(entry) {
  return new Promise((resolve) => {
    chrome.storage.local.get(['auditLog'], (r) => {
      const log = r.auditLog || [];
      log.push({ timestamp: new Date().toISOString(), ...entry });
      // Keep the existing 100-entry cap convention.
      const trimmed = log.slice(-100);
      chrome.storage.local.set({ auditLog: trimmed }, resolve);
    });
  });
}

// --- Active recon engine (light, read-only GET; gated) ---------------------
//
// Gating order: allowlist -> dry-run (report only) -> rate-limit -> fetch.
// Only HTTP GET is ever issued; no payloads are sent during recon.

async function fetchOne(url) {
  try {
    const res = await fetch(url, { method: 'GET', redirect: 'follow' });
    const text = await res.text();
    return {
      url,
      ok: res.ok,
      status: res.status,
      contentType: res.headers.get('content-type') || '',
      length: text.length,
      // Cap stored body to keep messages/storage reasonable.
      bodyPreview: text.slice(0, 4000),
    };
  } catch (e) {
    return { url, ok: false, status: 0, error: String(e && e.message) };
  }
}

async function runActiveRecon(pageUrl, discoveredEndpoints, opts = {}) {
  const { scope, dryRunMode } = await getSettings();
  const { allowed, host, reason } = evaluateScope(pageUrl, scope);

  if (!allowed) {
    return { success: false, reason: reason === 'out_of_scope' ? 'out_of_scope' : 'host_not_allowed', host };
  }

  // Build the target list: standard recon files always; discovered endpoints
  // only when explicitly requested (conservative default).
  const targets = [...buildReconFileUrls(pageUrl)];
  if (opts.includeDiscovered && Array.isArray(discoveredEndpoints)) {
    for (const ep of discoveredEndpoints) {
      const abs = normalizeEndpoint(ep, pageUrl);
      if (abs && !targets.includes(abs)) targets.push(abs);
    }
  }

  if (dryRunMode) {
    await appendAudit({
      action: 'ACTIVE_RECON',
      url: pageUrl,
      host,
      result: 'DRY_RUN',
      dryRun: true,
      wouldFetch: targets,
    });
    return { success: true, dryRun: true, wouldFetch: targets, host };
  }

  // Live: rate-limit each request, fetch, audit.
  const results = [];
  for (const url of targets) {
    if (!(await rateLimiter.canPerformAction())) {
      results.push({ url, ok: false, status: 0, error: 'rate_limited' });
      continue;
    }
    results.push(await fetchOne(url));
  }

  await appendAudit({
    action: 'ACTIVE_RECON',
    url: pageUrl,
    host,
    result: 'EXECUTED',
    dryRun: false,
    fetched: results.map((r) => ({ url: r.url, status: r.status, ok: r.ok })),
  });

  return { success: true, dryRun: false, results, host };
}

// Resolve a probe target to an absolute, IN-SCOPE URL. An absolute http(s)
// endpoint is allowed against ANY in-scope host (scope is the authorization
// boundary — e.g. escalation targets on a different subdomain than the tab); a
// relative endpoint is resolved against the page and must be same-origin.
function resolveScopedTarget(endpoint, pageUrl, scope) {
  let abs;
  if (typeof endpoint === 'string' && /^https?:\/\//i.test(endpoint)) {
    abs = endpoint;
  } else {
    abs = normalizeEndpoint(endpoint, pageUrl); // page-relative, same-origin
  }
  if (!abs) return { ok: false, reason: 'cross_origin_or_invalid' };
  const ev = evaluateScope(abs, scope);
  if (!ev.allowed) {
    return { ok: false, reason: ev.reason === 'out_of_scope' ? 'out_of_scope' : 'not_in_scope', host: ev.host };
  }
  return { ok: true, url: abs, host: ev.host };
}

async function probeEndpoint(pageUrl, endpoint) {
  const { scope, dryRunMode } = await getSettings();
  const t = resolveScopedTarget(endpoint, pageUrl, scope);
  if (!t.ok) {
    return { success: false, reason: t.reason, host: t.host, endpoint };
  }
  const abs = t.url;
  const host = t.host;
  if (dryRunMode) {
    await appendAudit({
      action: 'PROBE_ENDPOINT',
      url: pageUrl,
      host,
      result: 'DRY_RUN',
      dryRun: true,
      wouldFetch: [abs],
    });
    return { success: true, dryRun: true, wouldFetch: [abs] };
  }
  if (!(await rateLimiter.canPerformAction())) {
    return { success: false, reason: 'rate_limited' };
  }
  const result = await fetchOne(abs);
  await appendAudit({
    action: 'PROBE_ENDPOINT',
    url: pageUrl,
    host,
    result: 'EXECUTED',
    dryRun: false,
    fetched: { url: result.url, status: result.status, ok: result.ok },
  });
  return { success: true, dryRun: false, result };
}

// --- Differential / timing oracle (active confirmation; GET-only, gated) ----
//
// Sends benign request variants on ONE query param and lets the responses decide
// whether input reaches a backend sink (boolean or time-based). Read-only GETs,
// scope-gated on BOTH the page and the target URL, dry-run aware, rate-limited,
// audited. Emits a confidence-scored candidate finding — never a verdict.

async function fetchTimed(url) {
  const t0 = Date.now();
  try {
    const res = await fetch(url, { method: 'GET', redirect: 'follow', credentials: 'omit' });
    const text = await res.text();
    return { url, ok: res.ok, status: res.status, length: text.length, timeMs: Date.now() - t0 };
  } catch (e) {
    return { url, ok: false, status: 0, length: 0, timeMs: Date.now() - t0, error: String(e && e.message) };
  }
}

const fmtSummary = (s) => (s ? `${s.status}/${s.length}b/${s.timeMs}ms` : 'n/a');

async function differentialProbe(pageUrl, opts = {}) {
  const { scope, dryRunMode } = await getSettings();
  // The target may be a different (in-scope) host than the page — scope is the
  // gate, not same-origin-with-tab. resolveScopedTarget enforces that.
  const t = resolveScopedTarget(opts.url, pageUrl, scope);
  if (!t.ok) return { success: false, reason: t.reason, host: t.host };
  const baseUrl = t.url;
  const ev = { host: t.host };

  const param = opts.param || firstParam(baseUrl) || 'q';
  const baseVal = paramValue(baseUrl, param);
  const truthy = opts.truePayload != null ? opts.truePayload : " AND 1=1";
  const falsy = opts.falsePayload != null ? opts.falsePayload : " AND 1=2";

  const baselineUrl = buildVariantUrl(baseUrl, param, baseVal);
  const trueUrl = buildVariantUrl(baseUrl, param, baseVal + truthy);
  const falseUrl = buildVariantUrl(baseUrl, param, baseVal + falsy);
  const timeUrl = opts.timePayload ? buildVariantUrl(baseUrl, param, baseVal + opts.timePayload) : null;

  const plan = [baselineUrl, trueUrl, falseUrl].concat(timeUrl ? [timeUrl] : []);

  if (dryRunMode) {
    await appendAudit({ action: 'DIFFERENTIAL_PROBE', url: pageUrl, host: ev.host, result: 'DRY_RUN', dryRun: true, param, wouldFetch: plan });
    return { success: true, dryRun: true, param, wouldFetch: plan, host: ev.host };
  }

  const steps = [['base', baselineUrl], ['truthy', trueUrl], ['falsy', falseUrl]].concat(timeUrl ? [['delayed', timeUrl]] : []);
  const summaries = {};
  for (const [key, u] of steps) {
    if (!(await rateLimiter.canPerformAction())) {
      return { success: false, reason: 'rate_limited', param };
    }
    summaries[key] = await fetchTimed(u);
  }

  const diff = classifyDifferential({ base: summaries.base, truthy: summaries.truthy, falsy: summaries.falsy });
  const timing = timeUrl ? classifyTiming({ base: summaries.base, delayed: summaries.delayed }) : { signal: 'none', confidence: 0 };
  const best = timing.confidence > diff.confidence ? timing : diff;

  let path = baseUrl;
  try { path = new URL(baseUrl).pathname; } catch (_) {}

  const finding = best.signal !== 'none'
    ? {
        id: `oracle:${best.signal}:${param}:${path}`,
        host: ev.host,
        type: best.signal === 'time' ? 'sqli-time' : 'sqli-boolean',
        severity: 'high',
        confidence: best.confidence,
        title: `${best.signal === 'time' ? 'Time-based' : 'Boolean-based'} injection candidate on "${param}"`,
        evidence: `${best.detail}. base=${fmtSummary(summaries.base)} truthy=${fmtSummary(summaries.truthy)} falsy=${fmtSummary(summaries.falsy)}${timeUrl ? ` delayed=${fmtSummary(summaries.delayed)}` : ''}`,
        source: 'oracle',
        ref: 'CWE-89',
        // Depth for the escalation loop cap: a finding produced BY an escalation
        // step is one hop deeper than the finding that spawned it.
        depth: Number(opts.escalationDepth) || 0,
      }
    : null;

  await appendAudit({
    action: 'DIFFERENTIAL_PROBE', url: pageUrl, host: ev.host, result: 'EXECUTED',
    dryRun: false, param, signal: best.signal, confidence: best.confidence,
  });

  if (finding) await persistFindingsGrouped([finding]);

  return { success: true, dryRun: false, param, host: ev.host, summaries, diff, timing, finding };
}

// --- JS change monitoring (fetch → diff → persist → notify) ----------------

// Full-body fetch (fetchOne caps its preview; JS diffing needs the whole file).
async function fetchJsText(url) {
  try {
    const res = await fetch(url, { method: 'GET', redirect: 'follow' });
    const text = await res.text();
    return { url, ok: res.ok, status: res.status, text };
  } catch (e) {
    return { url, ok: false, status: 0, error: String(e && e.message) };
  }
}

async function appendJsWatch(host, diffs) {
  const r = await storageGet(['jsWatch']);
  const watch = r.jsWatch || {};
  const log = watch[host] || [];
  log.unshift({ ts: new Date().toISOString(), diffs });
  watch[host] = log.slice(0, 100); // cap history per host
  await storageSet({ jsWatch: watch });
}

async function fireNotification(host, diffs, notifyConfig) {
  const title = formatJsAlertTitle(host, diffs.length);
  const body = formatJsAlertBody(host, diffs);
  try {
    chrome.notifications.create('', {
      type: 'basic',
      iconUrl: 'icon-128.png',
      title,
      message: body.slice(0, 500),
    });
  } catch (_) {}
  // Optional outbound webhook to the user's own Telegram/Discord/Slack endpoint.
  if (notifyConfig && notifyConfig.webhookUrl) {
    try {
      const { body: payload } = buildWebhookPayload(notifyConfig.webhookPlatform, title, body);
      await fetch(notifyConfig.webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
    } catch (_) {}
  }
}

// Scan the in-scope JS files for a page, diff against stored snapshots, and
// alert on new attack surface. Scope-gated per script, rate-limited, dry-run aware.
async function scanJsFiles(pageUrl, opts = {}) {
  const { scope, dryRunMode, notifyConfig } = await getSettings();
  const pageEval = evaluateScope(pageUrl, scope);
  if (!pageEval.allowed) {
    return { success: false, reason: pageEval.reason, host: pageEval.host };
  }
  const host = pageEval.host;

  // Candidate scripts: what we've inventoried for this host, plus any explicit
  // list. Only fetch scripts whose OWN host is also in scope. Cap the batch.
  const invStore = await storageGet(['inventory']);
  const inv = (invStore.inventory || {})[host] || {};
  const candidates = Array.from(new Set([...(inv.scripts || []), ...((opts.scriptUrls) || [])]));
  const scripts = candidates.filter((u) => evaluateScope(u, scope).allowed).slice(0, 30);

  if (!scripts.length) {
    return { success: true, host, dryRun: dryRunMode, results: [], reason: 'no_in_scope_scripts' };
  }

  if (dryRunMode) {
    await appendAudit({ action: 'JS_SCAN', url: pageUrl, host, result: 'DRY_RUN', dryRun: true, wouldFetch: scripts });
    return { success: true, dryRun: true, host, wouldFetch: scripts, results: [] };
  }

  const snapStore = await storageGet(['jsSnapshots']);
  const snaps = snapStore.jsSnapshots || {};
  const results = [];
  const interesting = [];

  for (const url of scripts) {
    if (!(await rateLimiter.canPerformAction())) {
      results.push({ url, error: 'rate_limited' });
      continue;
    }
    const fetched = await fetchJsText(url);
    if (!fetched.ok) {
      results.push({ url, status: fetched.status, error: fetched.error || 'fetch_failed' });
      continue;
    }
    const next = makeSnapshot(url, fetched.text);
    const diff = diffSnapshots(snaps[url] || null, next);
    snaps[url] = next; // store the compact snapshot only — never the file body
    const entry = {
      url,
      isNew: diff.isNew,
      changed: diff.changed,
      summary: summarizeDiff(diff),
      addedEndpoints: diff.addedEndpoints,
      newSecrets: diff.newSecrets,
    };
    results.push(entry);
    if (isInterestingDiff(diff)) interesting.push(entry);
  }

  await storageSet({ jsSnapshots: snaps });
  if (interesting.length) await appendJsWatch(host, interesting);
  await appendAudit({
    action: 'JS_SCAN',
    url: pageUrl,
    host,
    result: 'EXECUTED',
    dryRun: false,
    scanned: scripts.length,
    interesting: interesting.length,
  });

  if (shouldNotify({ enabled: notifyConfig.enabled, hasInteresting: interesting.length > 0 })) {
    await fireNotification(host, interesting, notifyConfig);
  }

  return { success: true, dryRun: false, host, results, interesting: interesting.length };
}

// Periodic monitor: re-scan every host we hold snapshots for. Never runs in
// dry-run (it would do nothing) and is fully scope-gated inside scanJsFiles.
async function monitorTick() {
  const { scope, jsMonitor, dryRunMode } = await getSettings();
  if (!jsMonitor.enabled || dryRunMode) return;
  const snapStore = await storageGet(['jsSnapshots']);
  const hosts = new Set();
  for (const url of Object.keys(snapStore.jsSnapshots || {})) {
    const ev = evaluateScope(url, scope);
    if (ev.allowed) hosts.add(ev.host);
  }
  for (const host of hosts) {
    await scanJsFiles(`https://${host}/`, {});
  }
}

// --- Companion agent client (Phase 3) --------------------------------------
// Talks to the local Docker agent over http://localhost:PORT. The agent
// re-enforces scope server-side; this is just the transport.

async function getAgentConfig() {
  const r = await storageGet(['agentConfig']);
  return r.agentConfig || { url: 'http://localhost:8787', token: '' };
}

async function agentFetch(pathname, { method = 'GET', body, auth = true } = {}) {
  const cfg = await getAgentConfig();
  const base = (cfg.url || '').replace(/\/$/, '');
  if (!base) return { success: false, reason: 'no_agent_url' };
  const headers = { 'Content-Type': 'application/json' };
  if (auth) headers['x-agent-token'] = cfg.token || '';
  try {
    const res = await fetch(base + pathname, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await res.json().catch(() => ({}));
    return { success: res.ok, status: res.status, data };
  } catch (e) {
    return { success: false, reason: 'unreachable', error: String(e && e.message) };
  }
}

async function agentHealth() {
  return agentFetch('/health', { auth: false });
}

async function agentSyncScope() {
  const { scope } = await getSettings();
  return agentFetch('/scope', { method: 'PUT', body: scope });
}

async function agentWatches() {
  return agentFetch('/watches');
}
async function agentCreateWatch({ target, tools, intervalMinutes, profile }) {
  const { scope } = await getSettings();
  const ev = evaluateScope(/^https?:\/\//i.test(target) ? target : `https://${target}/`, scope);
  if (!ev.allowed) return { success: false, reason: ev.reason, host: ev.host };
  // Sync scope to the agent first — it re-checks server-side against its own copy.
  await agentFetch('/scope', { method: 'PUT', body: scope });
  return agentFetch('/watches', { method: 'POST', body: { target, tools, intervalMinutes, profile } });
}
async function agentDeleteWatch(id) {
  return agentFetch('/watch/' + encodeURIComponent(id), { method: 'DELETE' });
}
async function agentRunWatch(id) {
  return agentFetch('/watch/' + encodeURIComponent(id) + '/run', { method: 'POST' });
}

async function agentScan({ tool, target, profile }) {
  const { scope } = await getSettings();
  // Client-side scope pre-check for a fast, clear error; the agent re-checks too.
  const ev = evaluateScope(/^https?:\/\//i.test(target) ? target : `https://${target}/`, scope);
  if (!ev.allowed) return { success: false, reason: ev.reason, host: ev.host };
  // The agent keeps its OWN copy of scope and gates every scan against it. Push
  // ours first so an unsynced (or empty) agent scope can't reject in-scope targets.
  await agentFetch('/scope', { method: 'PUT', body: scope });
  const resp = await agentFetch('/scan', { method: 'POST', body: { tool, target, profile } });
  // Fold discovered hosts/endpoints back into the inventory when possible.
  if (resp.success && resp.data && ev.host) {
    try {
      await foldAgentResults(ev.host, resp.data);
    } catch (_) {}
  }
  return resp;
}

// Merge agent findings into the passive inventory so recon accumulates in one place.
async function foldAgentResults(host, data) {
  const obs = { pageUrl: `https://${host}/` };
  if (data.kind === 'subdomains' || data.kind === 'dns') {
    obs.links = (data.items || []).map((h) => `https://${String(h).split(/\s/)[0]}/`);
  } else if (data.kind === 'http') {
    obs.links = (data.items || []).map((i) => i.url).filter(Boolean);
  } else if (data.kind === 'urls') {
    // Content-discovery tools (katana/gau/ffuf/…) — fold URLs into endpoints+links.
    const urls = (data.items || []).filter((u) => typeof u === 'string' && u);
    obs.links = urls;
    obs.endpoints = urls;
  }
  if (obs.links && obs.links.length) {
    const r = await storageGet(['inventory']);
    const store = r.inventory || {};
    store[host] = mergeObservation(store[host], obs);
    await storageSet({ inventory: store });
  }
}

function syncMonitorAlarm() {
  chrome.storage.local.get(['jsMonitor'], (r) => {
    const m = r.jsMonitor || { enabled: false, intervalMinutes: 360 };
    try {
      chrome.alarms.clear('jsMonitor', () => {
        if (m.enabled) {
          chrome.alarms.create('jsMonitor', {
            periodInMinutes: Math.max(15, Number(m.intervalMinutes) || 360),
          });
        }
      });
    } catch (_) {}
  });
}

// Message handler
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'checkRateLimit') {
    (async () => {
      const canPerform = await rateLimiter.canPerformAction();
      const remaining = await rateLimiter.getRemainingActions();
      sendResponse({
        allowed: canPerform,
        remaining,
        message: canPerform ? 'Action allowed' : 'Rate limit exceeded',
      });
    })();
    return true; // async
  }

  if (request.action === 'activeRecon') {
    runActiveRecon(request.pageUrl, request.endpoints, {
      includeDiscovered: !!request.includeDiscovered,
    })
      .then(sendResponse)
      .catch((e) => sendResponse({ success: false, reason: String(e && e.message) }));
    return true; // async
  }

  if (request.action === 'probeEndpoint') {
    probeEndpoint(request.pageUrl, request.endpoint)
      .then(sendResponse)
      .catch((e) => sendResponse({ success: false, reason: String(e && e.message) }));
    return true; // async
  }

  if (request.action === 'differentialProbe') {
    differentialProbe(request.pageUrl, {
      url: request.url,
      param: request.param,
      truePayload: request.truePayload,
      falsePayload: request.falsePayload,
      timePayload: request.timePayload,
      escalationDepth: request.escalationDepth,
    })
      .then(sendResponse)
      .catch((e) => sendResponse({ success: false, reason: String(e && e.message) }));
    return true; // async
  }

  if (request.action === 'upsertFindings') {
    persistFindingsGrouped(request.findings || [])
      .then(sendResponse)
      .catch((e) => sendResponse({ success: false, reason: String(e && e.message) }));
    return true; // async
  }

  if (request.action === 'passiveObserve') {
    recordObservation(request.pageUrl, request.observation || {})
      .then(sendResponse)
      .catch((e) => sendResponse({ success: false, reason: String(e && e.message) }));
    return true; // async
  }

  if (request.action === 'scanJs') {
    scanJsFiles(request.pageUrl, { scriptUrls: request.scriptUrls })
      .then(sendResponse)
      .catch((e) => sendResponse({ success: false, reason: String(e && e.message) }));
    return true; // async
  }

  if (request.action === 'getApiSurface') {
    getApiSurface(request.pageUrl)
      .then(sendResponse)
      .catch((e) => sendResponse({ success: false, reason: String(e && e.message) }));
    return true; // async
  }

  if (request.action === 'probeApiSpec') {
    probeApiSpec(request.pageUrl)
      .then(sendResponse)
      .catch((e) => sendResponse({ success: false, reason: String(e && e.message) }));
    return true; // async
  }

  if (request.action === 'saveApiFindings') {
    saveApiFindings(request.pageUrl, request.specUrl, request.specEndpoints)
      .then(sendResponse)
      .catch((e) => sendResponse({ success: false, reason: String(e && e.message) }));
    return true; // async
  }

  if (request.action === 'agentHealth') {
    agentHealth().then(sendResponse).catch((e) => sendResponse({ success: false, reason: String(e && e.message) }));
    return true; // async
  }

  if (request.action === 'agentSyncScope') {
    agentSyncScope().then(sendResponse).catch((e) => sendResponse({ success: false, reason: String(e && e.message) }));
    return true; // async
  }

  if (request.action === 'agentScan') {
    agentScan({ tool: request.tool, target: request.target, profile: request.profile })
      .then(sendResponse)
      .catch((e) => sendResponse({ success: false, reason: String(e && e.message) }));
    return true; // async
  }

  if (request.action === 'agentWatches') {
    agentWatches().then(sendResponse).catch((e) => sendResponse({ success: false, reason: String(e && e.message) }));
    return true;
  }
  if (request.action === 'agentCreateWatch') {
    agentCreateWatch(request).then(sendResponse).catch((e) => sendResponse({ success: false, reason: String(e && e.message) }));
    return true;
  }
  if (request.action === 'agentDeleteWatch') {
    agentDeleteWatch(request.id).then(sendResponse).catch((e) => sendResponse({ success: false, reason: String(e && e.message) }));
    return true;
  }
  if (request.action === 'agentRunWatch') {
    agentRunWatch(request.id).then(sendResponse).catch((e) => sendResponse({ success: false, reason: String(e && e.message) }));
    return true;
  }
});

// Passive security-header analysis: observe response headers on in-scope hosts.
// Non-blocking listener; 'extraHeaders' is required to read Set-Cookie and some
// security headers in MV3. Wrapped in try/catch so a missing permission or an
// unsupported extraInfoSpec never breaks worker startup.
try {
  chrome.webRequest.onHeadersReceived.addListener(
    (details) => { handleHeadersReceived(details); },
    { urls: ['http://*/*', 'https://*/*'], types: ['main_frame', 'sub_frame', 'xmlhttprequest'] },
    ['responseHeaders', 'extraHeaders']
  );
} catch (_) {
  try {
    // Fallback without extraHeaders if the platform rejects it.
    chrome.webRequest.onHeadersReceived.addListener(
      (details) => { handleHeadersReceived(details); },
      { urls: ['http://*/*', 'https://*/*'], types: ['main_frame', 'sub_frame', 'xmlhttprequest'] },
      ['responseHeaders']
    );
  } catch (_) {}
}

// Passive API surface discovery: observe request line + headers of XHR/fetch on
// in-scope hosts. requestHeaders (+extraHeaders) let us note whether the call
// carried auth; observe-only, never blocking.
try {
  chrome.webRequest.onSendHeaders.addListener(
    (details) => { recordApiRequest(details); },
    { urls: ['http://*/*', 'https://*/*'], types: ['xmlhttprequest'] },
    ['requestHeaders', 'extraHeaders']
  );
} catch (_) {
  try {
    chrome.webRequest.onSendHeaders.addListener(
      (details) => { recordApiRequest(details); },
      { urls: ['http://*/*', 'https://*/*'], types: ['xmlhttprequest'] },
      ['requestHeaders']
    );
  } catch (_) {}
}

// Monitoring alarm: re-scan tracked hosts on a schedule.
try {
  chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm && alarm.name === 'jsMonitor') monitorTick();
  });
} catch (_) {}
syncMonitorAlarm();
chrome.storage.onChanged.addListener((changes, ns) => {
  if (ns === 'local' && changes.jsMonitor) syncMonitorAlarm();
});

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(['allowlist', 'scope', 'dryRunMode', 'auditLog', 'notifyConfig', 'jsMonitor', 'agentConfig'], (result) => {
    const patch = {};
    if (!result.allowlist) patch.allowlist = ['*'];
    if (!result.scope) patch.scope = { inScope: ['*'], outOfScope: [] };
    if (result.dryRunMode === undefined) patch.dryRunMode = true;
    if (!result.auditLog) patch.auditLog = [];
    if (!result.notifyConfig) patch.notifyConfig = { enabled: true, webhookUrl: '', webhookPlatform: 'discord' };
    if (!result.jsMonitor) patch.jsMonitor = { enabled: false, intervalMinutes: 360 };
    if (!result.agentConfig) patch.agentConfig = { url: 'http://localhost:8787', token: '' };
    if (Object.keys(patch).length) chrome.storage.local.set(patch);
  });
});

chrome.storage.local.get(['dryRunMode'], (result) => {
  if (result.dryRunMode) {
    chrome.action.setBadgeText({ text: 'DRY' });
    chrome.action.setBadgeBackgroundColor({ color: '#FF9800' });
  } else {
    chrome.action.setBadgeText({ text: '' });
  }
});

chrome.storage.onChanged.addListener((changes, namespace) => {
  if (changes.dryRunMode) {
    if (changes.dryRunMode.newValue) {
      chrome.action.setBadgeText({ text: 'DRY' });
      chrome.action.setBadgeBackgroundColor({ color: '#FF9800' });
    } else {
      chrome.action.setBadgeText({ text: '' });
    }
  }
});
