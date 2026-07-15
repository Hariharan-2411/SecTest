// Recon executor — Phase 5.2. Runs a validated tool call against the companion
// agent and normalizes the result into findings. IMPURE only through an INJECTED
// agent client (no direct network), so it is fully testable offline. Never throws.
//
// Pairs with reconAgent.js (the guardrail layer): you validate a call with
// normalizeToolCall, then — if allowed/approved — execute it here. The companion
// agent re-checks scope server-side regardless, so this is defense in depth.

import { normalizeFinding, FINDING_SEVERITIES } from './findings';

/** Map a nuclei severity onto the finding severity set. Pure. */
export function mapNucleiSeverity(sev) {
  const s = String(sev || '').toLowerCase();
  if (s === 'info') return 'informational';
  return FINDING_SEVERITIES.includes(s) ? s : 'medium';
}

/**
 * Extract normalized findings from a /scan 200 body. Only nuclei
 * (`kind: 'findings'`) yields findings today; other tools return recon surface
 * (subdomains/urls/ports) which the caller reads from `items`, not here. Pure.
 */
export function toFindings(body = {}) {
  if (!body || body.kind !== 'findings' || !Array.isArray(body.items))
    return [];
  const host = body.host || '';
  return body.items.map((it) =>
    normalizeFinding({
      type: 'nuclei',
      host,
      severity: mapNucleiSeverity(it && it.severity),
      title: (it && (it.name || it.templateId)) || 'nuclei finding',
      evidence: (it && it.matched) || '',
      ref: (it && it.templateId) || '',
      source: 'nuclei',
    })
  );
}

function fail(tool, target, status, error, host = '') {
  return {
    ok: false,
    tool,
    target,
    host,
    status,
    error,
    kind: null,
    items: [],
    count: 0,
    findings: [],
  };
}

/**
 * Execute a validated recon call via the injected agent client. Never throws.
 * @param {{tool,target,profile,risk?}} call  (from reconAgent.normalizeToolCall)
 * @param {{agentClient:{scan:Function}}} deps
 * @returns {Promise<object>} result with normalized findings + recon surface
 */
export async function executeReconTool(call = {}, { agentClient } = {}) {
  const { tool, target, profile } = call;
  if (!agentClient || typeof agentClient.scan !== 'function') {
    return fail(tool, target, 0, 'no_agent_client');
  }
  let status;
  let body;
  try {
    ({ status, body } = await agentClient.scan({ tool, target, profile }));
  } catch (_) {
    return fail(tool, target, 0, 'call_failed');
  }
  body = body || {};
  if (status !== 200) {
    return fail(
      tool,
      target,
      status,
      (typeof body.error === 'string' && body.error) || `status_${status}`,
      body.host || ''
    );
  }
  const items = Array.isArray(body.items) ? body.items : [];
  return {
    ok: true,
    tool,
    target,
    host: body.host || '',
    status,
    error: null,
    kind: body.kind || null,
    items,
    count: typeof body.count === 'number' ? body.count : items.length,
    findings: toFindings(body),
  };
}

/**
 * Build a concrete agent client over an injected `fetchImpl` (defaults to global
 * fetch). The real recon path uses this; tests inject a fake fetch. Sends the
 * `x-agent-token` header the companion agent requires.
 */
export function makeAgentClient({
  baseUrl = 'http://localhost:8787',
  token = '',
  fetchImpl,
} = {}) {
  const doFetch = fetchImpl || (typeof fetch !== 'undefined' ? fetch : null);
  return {
    async scan({ tool, target, profile }) {
      if (!doFetch) throw new Error('no_fetch');
      const res = await doFetch(`${baseUrl}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-agent-token': token },
        body: JSON.stringify({ tool, target, profile }),
      });
      let body = {};
      try {
        body = await res.json();
      } catch (_) {
        /* non-JSON error body */
      }
      return { status: res.status, body };
    },
  };
}
