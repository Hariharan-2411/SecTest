// AI escalation plan — pure, unit-testable (no chrome.*/network).
//
// The AI planner (escalateFinding) returns a raw "plan": a list of proposed next
// steps to escalate a finding. This module is the SAFETY CONTRACT between the
// model and the engine: it validates that plan into typed, scope-checked,
// risk-tagged ActionSteps that map 1:1 to actions the engine already runs safely.
//
// GUARANTEES (enforced here, never trusted from the model):
//   • Only allow-listed verbs execute; unknown verbs degrade to a `manual` note.
//   • `risk` is RECOMPUTED from the verb/tool — the model's claimed risk is ignored.
//   • Every url/host target is re-checked with evaluateScope; out-of-scope →
//     downgraded to a `manual` note (never executed).
//   • The step count is capped; overflow is rejected, not run.
//
// Nothing here executes anything — it only classifies and maps. Execution stays
// in the content/background handlers behind their existing dry-run/confirm/rate
// guardrails.

import { evaluateScope } from './scope';

// Payload families the engine can actually run (mirror of utils/payloads.js keys).
export const VULN_FAMILIES = ['xss', 'sqli', 'cmdi', 'pathTraversal', 'ssrf', 'xpath', 'ldap'];

// Agent tools considered read-only/passive (used to tag agent_scan risk).
const AGENT_SAFE_TOOLS = new Set(['subfinder', 'dnsx', 'httpx', 'gau', 'waybackurls']);

// The allowlist. `targetKind`:
//   'url'  — needs an in-scope URL target (scope-checked here)
//   'host' — needs an in-scope host/url target (scope-checked here)
//   'none' — runs against the CURRENT page/selected fields (gated at exec time)
export const ACTION_VERBS = {
  deep_js:            { risk: 'safe',   targetKind: 'none' },
  confirm_reflection: { risk: 'safe',   targetKind: 'none' },
  probe_endpoint:     { risk: 'safe',   targetKind: 'url' },
  run_payload:        { risk: 'active', targetKind: 'none' },
  differential_probe: { risk: 'active', targetKind: 'url' },
  agent_scan:         { risk: 'active', targetKind: 'host' },
  manual:             { risk: 'none',   targetKind: 'none' },
};

export const MAX_STEPS = 12;

let _seq = 0;
function stepId() {
  _seq = (_seq + 1) % 1e9;
  return `esc_${Date.now().toString(36)}_${_seq}`;
}

function str(v, max = 400) {
  return typeof v === 'string' ? v.slice(0, max) : '';
}

// Turn a bare host into a URL so evaluateScope (which parses URLs) can check it.
function targetUrl(target) {
  const t = str(target, 2000).trim();
  if (!t) return '';
  return /^https?:\/\//i.test(t) ? t : `https://${t.replace(/^\/+/, '')}`;
}

// Build a `manual` note step (nothing executes; the human reads the guidance).
function manualStep(raw, reason) {
  return {
    id: stepId(),
    type: 'manual',
    risk: 'none',
    note: str(raw && raw.rationale) || str(raw && raw.note) || 'No details provided.',
    rationale: str(raw && raw.rationale),
    reason, // why it became manual (unknown_verb / out_of_scope / bad_target / …), or undefined
  };
}

// Recompute risk from the verb (and tool for agent_scan). Never trust the model.
function riskFor(type, tool) {
  if (type === 'agent_scan') return AGENT_SAFE_TOOLS.has(tool) ? 'safe' : 'active';
  return (ACTION_VERBS[type] && ACTION_VERBS[type].risk) || 'active';
}

/**
 * Normalize ONE raw step against scope. Returns a valid ActionStep, or a
 * `manual` fallback carrying the reason it couldn't be executed.
 */
export function normalizeStep(raw = {}, { scope, host } = {}) {
  const type = raw && typeof raw.type === 'string' ? raw.type : '';
  const def = ACTION_VERBS[type];
  if (!def) return manualStep(raw, `unknown_verb:${type || '(none)'}`);
  if (type === 'manual') return manualStep(raw);

  // run_payload must name a family the engine can run.
  if (type === 'run_payload' && !VULN_FAMILIES.includes(raw.payloadFamily)) {
    return manualStep(raw, `unknown_family:${str(raw.payloadFamily, 40) || '(none)'}`);
  }

  // Scope-check targeted verbs.
  let target = '';
  if (def.targetKind === 'url' || def.targetKind === 'host') {
    const url = targetUrl(raw.target);
    if (!url) return manualStep(raw, 'bad_target');
    const ev = evaluateScope(url, scope || { inScope: [], outOfScope: [] });
    if (!ev.allowed) return manualStep(raw, `out_of_scope:${ev.reason}`);
    target = def.targetKind === 'host' ? ev.host : url;
  }

  return {
    id: stepId(),
    type,
    risk: riskFor(type, raw.tool),
    target: target || undefined,
    param: str(raw.param, 100) || undefined,
    payloadFamily: type === 'run_payload' ? raw.payloadFamily : undefined,
    tool: type === 'agent_scan' ? str(raw.tool, 40) || undefined : undefined,
    profile: type === 'agent_scan' ? str(raw.profile, 40) || undefined : undefined,
    rationale: str(raw.rationale),
    expectedSignal: str(raw.expectedSignal),
    host: host || undefined,
  };
}

/**
 * Normalize a raw plan (`{steps:[…]}` or an array) into executable ActionSteps
 * plus a `rejected` list (overflow beyond MAX_STEPS). Manual/downgraded steps
 * stay IN `steps` (they're shown as read-only guidance) with a `reason`.
 * @returns {{steps: object[], rejected: {raw:object, reason:string}[]}}
 */
export function normalizePlan(rawPlan, { scope, host } = {}) {
  const list = Array.isArray(rawPlan)
    ? rawPlan
    : Array.isArray(rawPlan && rawPlan.steps)
      ? rawPlan.steps
      : [];
  const steps = [];
  const rejected = [];
  for (const raw of list) {
    if (steps.length >= MAX_STEPS) {
      rejected.push({ raw, reason: 'over_cap' });
      continue;
    }
    steps.push(normalizeStep(raw, { scope, host }));
  }
  return { steps, rejected };
}

/**
 * Map an executable ActionStep to the concrete engine message the popup sends.
 * Returns { engine: 'content'|'background', message } or null for manual/no-op.
 * (The popup resolves run_payload's actual payloads from the library.)
 */
export function mapStepToAction(step = {}) {
  switch (step.type) {
    case 'deep_js':
      return { engine: 'content', message: { action: 'deepJsScan' } };
    case 'confirm_reflection':
      return { engine: 'content', message: { action: 'confirmReflection' } };
    case 'run_payload':
      return { engine: 'content', message: { action: 'executeVulnTest', vulnKey: step.payloadFamily } };
    case 'probe_endpoint':
      return { engine: 'background', message: { action: 'probeEndpoint', endpoint: step.target } };
    case 'differential_probe':
      return { engine: 'background', message: { action: 'differentialProbe', url: step.target, param: step.param } };
    case 'agent_scan':
      return { engine: 'background', message: { action: 'agentScan', tool: step.tool, target: step.target, profile: step.profile } };
    default:
      return null; // manual or unknown → nothing to execute
  }
}

/** True when a step is safe to run without an active-tool confirmation. */
export function isSafeStep(step) {
  return !!step && step.risk === 'safe';
}

// --- feedback-loop bounds ---------------------------------------------------
// The escalation loop (finding → steps → new findings → escalate again) must
// never run away on traffic or cost. Two independent caps enforce that:
//   • depth — how many escalation hops deep a finding is (a finding produced BY
//     an escalation carries depth+1); escalation stops at MAX_DEPTH.
//   • budget — total escalation steps executed this popup session.
// There are no timers and no background auto-run: the human triggers every hop.

export const MAX_DEPTH = 2;
export const DEFAULT_ESCALATION_BUDGET = 25;

/** May a finding at `depth` still be escalated, given the session `budgetUsed`? */
export function canEscalate({ depth = 0, budgetUsed = 0, maxDepth = MAX_DEPTH, budget = DEFAULT_ESCALATION_BUDGET } = {}) {
  return depth < maxDepth && budgetUsed < budget;
}

/** Remaining escalation-step budget for the session (never negative). */
export function remainingBudget(budgetUsed = 0, budget = DEFAULT_ESCALATION_BUDGET) {
  return Math.max(0, budget - budgetUsed);
}
