console.log('SecTest Pro - Background Service Worker');

import {
  buildReconFileUrls,
  normalizeEndpoint,
  hostFromUrl,
  isHostAllowed,
} from '../../utils/reconHelpers';

// Rate limiting
const rateLimiter = {
  actions: [],
  maxActionsPerMinute: 20,

  canPerformAction() {
    const now = Date.now();
    const oneMinuteAgo = now - 60000;
    this.actions = this.actions.filter(time => time > oneMinuteAgo);
    if (this.actions.length >= this.maxActionsPerMinute) {
      return false;
    }
    this.actions.push(now);
    return true;
  },

  getRemainingActions() {
    const now = Date.now();
    const oneMinuteAgo = now - 60000;
    this.actions = this.actions.filter(time => time > oneMinuteAgo);
    return this.maxActionsPerMinute - this.actions.length;
  }
};

const payloadValidator = {
  dangerousPatterns: [
    /<script[\s\S]*?>/i,
    /javascript:/i,
    /on\w+\s*=/i,
    /eval\s*\(/i,
    /DROP\s+TABLE/i,
    /DELETE\s+FROM/i,
    /INSERT\s+INTO/i,
    /UPDATE\s+.*SET/i,
    /UNION\s+SELECT/i,
    /exec\s*\(/i,
    /\.\.\/\.\.\//g,
  ],

  isSafe(payload, targetHost) {
    const sanctionedLabs = ['*', 'dvwa', 'localhost', '127.0.0.1', 'google', 'webgoat', 'hackazon'];
    const isSanctioned = sanctionedLabs.includes('*') || sanctionedLabs.some(lab => targetHost.includes(lab));

    if (isSanctioned) {
      return { safe: true, reason: 'Sanctioned lab target' };
    }

    for (const pattern of this.dangerousPatterns) {
      if (pattern.test(payload)) {
        return {
          safe: false,
          reason: `Dangerous pattern detected: ${pattern.toString()}`
        };
      }
    }

    return { safe: true, reason: 'Passed validation' };
  }
};

// --- Settings & audit helpers (Promise-wrapped chrome.storage) -------------

function getSettings() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['allowlist', 'dryRunMode', 'auditLog'], (r) => {
      resolve({
        allowlist: r.allowlist || ['*'],
        dryRunMode: r.dryRunMode !== false, // default true
        auditLog: r.auditLog || [],
      });
    });
  });
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
  const { allowlist, dryRunMode } = await getSettings();
  const host = hostFromUrl(pageUrl);

  if (!isHostAllowed(allowlist, host)) {
    return { success: false, reason: 'host_not_allowed', host };
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
    if (!rateLimiter.canPerformAction()) {
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

async function probeEndpoint(pageUrl, endpoint) {
  const { allowlist, dryRunMode } = await getSettings();
  const host = hostFromUrl(pageUrl);

  if (!isHostAllowed(allowlist, host)) {
    return { success: false, reason: 'host_not_allowed', host };
  }
  const abs = normalizeEndpoint(endpoint, pageUrl);
  if (!abs) {
    return { success: false, reason: 'cross_origin_or_invalid', endpoint };
  }
  if (dryRunMode) {
    await appendAudit({
      action: 'PROBE_ENDPOINT',
      url: pageUrl,
      host,
      result: 'DRY_RUN',
      dryRun: true,
      wouldFetch: [abs],
    });
    return { success: true, dryRun: true, wouldFetch: abs };
  }
  if (!rateLimiter.canPerformAction()) {
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

// Message handler
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'checkRateLimit') {
    const canPerform = rateLimiter.canPerformAction();
    const remaining = rateLimiter.getRemainingActions();
    sendResponse({
      allowed: canPerform,
      remaining: remaining,
      message: canPerform ? 'Action allowed' : 'Rate limit exceeded'
    });
    return true;
  }

  if (request.action === 'validatePayload') {
    const validation = payloadValidator.isSafe(request.payload, request.host);
    sendResponse(validation);
    return true;
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
});

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(['allowlist', 'dryRunMode', 'auditLog'], (result) => {
    if (!result.allowlist) {
      chrome.storage.local.set({
        allowlist: ['*'],
        dryRunMode: true,
        auditLog: []
      });
    }
  });
});

chrome.storage.local.get(['dryRunMode'], (result) => {
  if (result.dryRunMode) {
    chrome.action.setBadgeText({ text: 'DRY' });
    chrome.action.setBadgeBackgroundColor({ color: '#FF9800' });
  } else {
    chrome.action.setBadgeText({ text: 'LIVE' });
    chrome.action.setBadgeBackgroundColor({ color: '#4CAF50' });
  }
});

chrome.storage.onChanged.addListener((changes, namespace) => {
  if (changes.dryRunMode) {
    if (changes.dryRunMode.newValue) {
      chrome.action.setBadgeText({ text: 'DRY' });
      chrome.action.setBadgeBackgroundColor({ color: '#FF9800' });
    } else {
      chrome.action.setBadgeText({ text: 'LIVE' });
      chrome.action.setBadgeBackgroundColor({ color: '#4CAF50' });
    }
  }
});
