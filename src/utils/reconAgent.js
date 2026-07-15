// Recon agent — pure guardrail layer (Phase 5.1). No chrome.*/network/SDK.
//
// The SAFETY CONTRACT between an LLM recon planner and the companion agent:
// given a proposed tool call, it validates the tool + target + risk + budget
// before anything could run. Same posture as escalation.js / chains.js — the
// model proposes, the code decides what's allowed.
//
// GUARANTEES (enforced here, never trusted from the model):
//   • Only registered recon tools run; unknown tools are denied.
//   • `risk` is RECOMPUTED from the registry — the model's claim is ignored.
//   • Targets are re-checked against scope; out-of-scope → denied.
//   • Risk policy: safe → auto-allow, active → human approval, destructive → deny.
//   • Per-run budget and plan step-count are capped.
//
// Nothing here executes — execution is Phase 5.2 (DI executors). Mirrors the
// companion agent's own TOOLS registry (agent/lib/tools.js) so risk tags agree.

import { evaluateScope, EMPTY_SCOPE } from './scope';
import { sortFindings } from './findings';

// Risk tags mirror agent/lib/tools.js exactly.
export const RECON_TOOLS = {
  subfinder: { risk: 'safe' },
  dnsx: { risk: 'safe' },
  httpx: { risk: 'safe' },
  gau: { risk: 'safe' },
  waybackurls: { risk: 'safe' },
  naabu: { risk: 'active' },
  nmap: { risk: 'active' },
  nuclei: { risk: 'active' },
  katana: { risk: 'active' },
  ffuf: { risk: 'active' },
  feroxbuster: { risk: 'active' },
};

// Profiles the companion agent understands (PORT_PROFILES / nmap / CRAWL_DEPTH).
export const RECON_PROFILES = ['quick', 'top1000', 'services', 'deep'];
const DEFAULT_PROFILE = 'quick';

// Default policy: safe auto-runs, active needs a human, destructive is denied.
export const RISK_POLICY = {
  safe: 'allow',
  active: 'needs_approval',
  destructive: 'deny',
};

export const MAX_RECON_STEPS = 12;
export const DEFAULT_RECON_BUDGET = 20;

function str(v) {
  return typeof v === 'string' ? v : '';
}

function deny(reason) {
  return { decision: 'deny', reason, call: null };
}

// Turn a bare host into a URL so evaluateScope (which parses URLs) can check it.
function targetUrl(target) {
  const t = str(target).trim();
  if (!t) return '';
  return /^https?:\/\//i.test(t) ? t : `https://${t.replace(/^\/+/, '')}`;
}

// Map a recomputed risk to a decision via the policy. Unknown → deny.
function decideByRisk(risk, policy) {
  const action = policy[risk];
  if (action === 'allow') return { decision: 'allow', reason: '' };
  if (action === 'needs_approval')
    return { decision: 'needs_approval', reason: `${risk}_tool` };
  return { decision: 'deny', reason: `risk_denied:${risk}` };
}

/**
 * Validate ONE proposed tool call against the registry + scope + policy + budget.
 * Pure. @returns {{decision:'allow'|'needs_approval'|'deny', reason:string, call:object|null}}
 */
export function normalizeToolCall(
  raw = {},
  {
    scope,
    policy = RISK_POLICY,
    budgetUsed = 0,
    budget = DEFAULT_RECON_BUDGET,
  } = {}
) {
  const tool = str(raw.tool);
  const def = RECON_TOOLS[tool];
  if (!def) return deny(`unknown_tool:${tool || '(none)'}`);

  const target = str(raw.target).trim();
  const url = targetUrl(target);
  if (!url) return deny('bad_target');

  const ev = evaluateScope(url, scope || EMPTY_SCOPE);
  if (!ev.allowed) return deny(`out_of_scope:${ev.reason}`);

  if (budgetUsed >= budget) return deny('over_budget');

  const risk = def.risk; // recomputed from the registry; the model's claim is ignored
  const profile = RECON_PROFILES.includes(raw.profile)
    ? raw.profile
    : DEFAULT_PROFILE;
  const rd = decideByRisk(risk, policy);
  if (rd.decision === 'deny')
    return { decision: 'deny', reason: rd.reason, call: null };
  return {
    decision: rd.decision,
    reason: rd.reason,
    call: { tool, target, profile, risk },
  };
}

/**
 * Validate a whole recon plan (`{steps:[…]}` / `{tools:[…]}` / array). Caps the
 * step count. Pure. @returns {{steps:object[], rejected:{raw:object,reason:string}[]}}
 */
export function normalizeReconPlan(rawPlan, opts = {}) {
  const list = Array.isArray(rawPlan)
    ? rawPlan
    : Array.isArray(rawPlan && rawPlan.steps)
    ? rawPlan.steps
    : Array.isArray(rawPlan && rawPlan.tools)
    ? rawPlan.tools
    : [];
  const steps = [];
  const rejected = [];
  for (const raw of list) {
    if (steps.length >= MAX_RECON_STEPS) {
      rejected.push({ raw, reason: 'over_cap' });
      continue;
    }
    steps.push(normalizeToolCall(raw, opts));
  }
  return { steps, rejected };
}

/**
 * Rank findings into a triage draft: severity (critical→info) then confidence,
 * with a 1-based rank. Pure; returns a new array.
 */
export function rankTriage(findings) {
  return sortFindings(Array.isArray(findings) ? findings : []).map((f, i) => ({
    ...f,
    rank: i + 1,
  }));
}
