// Recon agent loop — Phase 5.3. A bounded, hand-rolled plan→validate→execute
// loop that composes the guardrail layer (reconAgent) + the executor
// (reconExecutor) + an LLM planner. IMPURE only through injected `chat`,
// `agentClient`, and `approve` hooks, so it is fully testable offline. It NEVER
// throws, never auto-submits, and stops at a depth/budget cap.
//
// Not a vendor SDK — the same JSON-plan pattern proven in chains.js/escalation.js:
// the LLM proposes recon steps as JSON, the pure layer decides what may run,
// approved safe steps run, active steps require a human `approve` hook.

import {
  RECON_TOOLS,
  RECON_PROFILES,
  RISK_POLICY,
  DEFAULT_RECON_BUDGET,
  normalizeReconPlan,
} from './reconAgent';
import { executeReconTool } from './reconExecutor';
import { finalizeTriage } from './reconTriage';
import * as ai from './aiProvider';

export const MAX_RECON_DEPTH = 6;

// Injection/confirmation tools that must hit a parameter-bearing endpoint, not the
// host root (a root has nothing to inject). Must match the destructive/active
// injection tools in agent/lib/tools.js.
const INJECTION_TOOLS = new Set(['dalfox', 'sqlmap', 'sstimap', 'commix', 'crlfuzz']);

function hostOf(t) {
  try {
    return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(t) ? t : 'http://' + t).hostname.toLowerCase();
  } catch (_) {
    return '';
  }
}

/**
 * Deterministically choose the best injection target for `host`: the discovered
 * same-host URL with the MOST query parameters, else `fallback`. Pure. This is
 * what makes injection tools hit `/search?q=` instead of the useless root.
 */
export function pickInjectionTarget(host, surfaceUrls = [], fallback) {
  const h = String(host || '').toLowerCase();
  const cands = [];
  for (const u of Array.isArray(surfaceUrls) ? surfaceUrls : []) {
    if (typeof u !== 'string') continue;
    let parsed;
    try {
      parsed = new URL(u);
    } catch (_) {
      continue;
    }
    if (parsed.hostname.toLowerCase() !== h) continue; // same host only (scope-safe)
    const n = [...parsed.searchParams.keys()].length;
    if (n === 0) continue; // must carry a parameter to inject
    cands.push({ u, n });
  }
  if (!cands.length) return fallback;
  cands.sort((a, b) => b.n - a.n);
  return cands[0].u;
}

// Decision strictness ranking for the optional critic. The critic may only
// TIGHTEN (raise the rank), never loosen — so a second model can make a run more
// conservative but can never bypass scope/policy or the human-approval gate.
const DECISION_RANK = { allow: 0, needs_approval: 1, deny: 2 };
export function stricterDecision(original, critic) {
  const ro = DECISION_RANK[original] ?? 0;
  const rc = DECISION_RANK[critic];
  if (rc === undefined) return original; // unknown critic verdict → ignore
  return rc > ro ? critic : original;
}

// Apply an optional critic hook to normalized steps. `critique(steps, context)`
// returns a verdict per step ('allow'|'needs_approval'|'deny' or {decision,reason}).
// On any failure or shape mismatch, the original steps are kept unchanged — the
// critic is pure hardening and can never loosen a decision.
async function applyCritique(steps, context, critique) {
  if (typeof critique !== 'function' || !steps.length) return steps;
  let verdicts;
  try {
    verdicts = await critique(steps, context);
  } catch (_) {
    return steps;
  }
  if (!Array.isArray(verdicts) || verdicts.length !== steps.length) return steps;
  return steps.map((s, i) => {
    const v = verdicts[i];
    const cd = typeof v === 'string' ? v : v && v.decision;
    const merged = stricterDecision(s.decision, cd);
    if (merged === s.decision) return s;
    const why = (v && typeof v === 'object' && v.reason) || cd || 'tightened';
    return { ...s, decision: merged, reason: `critic:${why}` };
  });
}

// kind (from the companion agent's parseOutput) -> surface bucket.
const SURFACE_BUCKET = {
  subdomains: 'subdomains',
  dns: 'subdomains',
  http: 'hosts',
  ports: 'ports',
  urls: 'urls',
};

function safeParse(text) {
  if (typeof text !== 'string') return null;
  let t = text.trim();
  const fence = t.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence) t = fence[1].trim();
  if (!t.startsWith('{') && !t.startsWith('[')) {
    const i = t.indexOf('{');
    const j = t.lastIndexOf('}');
    if (i !== -1 && j > i) t = t.slice(i, j + 1);
  }
  try {
    return JSON.parse(t);
  } catch (_) {
    return null;
  }
}

/**
 * Build the bounded planner prompt from the loop context. Pure.
 * @returns {{messages:{role:string,content:string}[]}}
 */
export function buildReconPrompt(context = {}) {
  const scope = context.scope || { inScope: [] };
  const targets = (Array.isArray(scope.inScope) ? scope.inScope : []).slice(
    0,
    20
  );
  const s = context.surface || {};
  const seedUrls = (s.urls || []).slice(0, 15);
  const remaining = Math.max(
    0,
    (context.budget || DEFAULT_RECON_BUDGET) - (context.budgetUsed || 0)
  );
  const done = (Array.isArray(context.executed) ? context.executed : [])
    .filter((e) => e && e.ran)
    .map((e) => `${e.call && e.call.tool}:${e.call && e.call.target}`)
    .slice(0, 30);
  const content =
    'You are a bug-bounty recon planner. Goal: enumerate in-scope assets and surface known vulnerabilities using ONLY the allowed tools, staying strictly in scope. ' +
    `Allowed tools: ${Object.keys(RECON_TOOLS).join(
      ', '
    )}. Profiles: ${RECON_PROFILES.join(', ')}. ` +
    `In-scope targets: ${targets.join(', ') || '(none)'}. ` +
    `Known endpoints (use these EXACT URLs as the target when scanning, keeping their scheme and port): ${seedUrls.join(', ') || '(none)'}. ` +
    `Already run: ${done.join(', ') || '(none)'}. ` +
    `Discovered so far: ${(s.subdomains || []).length} subdomains, ${
      (s.hosts || []).length
    } hosts, ${(s.urls || []).length} urls, ${(s.ports || []).length} ports; ${
      (context.findings || []).length
    } findings. ` +
    `Budget remaining: ${remaining} tool runs. ` +
    'STRATEGY: discovery is only the first step — do NOT spend the whole budget enumerating. ' +
    'As soon as you have endpoints (the Known endpoints above, or once katana/gau/httpx have run), ' +
    'spend most of the remaining budget TESTING those exact endpoint URLs for vulnerabilities with the ' +
    'vuln/injection tools: nuclei, dalfox (XSS), sqlmap (SQLi), crlfuzz (CRLF), sstimap (SSTI), ' +
    'commix (command injection), jwt_tool, subzy (takeover), s3scanner, wpscan. Target the discovered ' +
    'endpoint URLs, not just the root. ' +
    'Propose the next 1-3 recon steps as JSON only: {"steps":[{"tool","target","profile"}],"done":false}. ' +
    'Reference only in-scope targets and allowed tools. Set done:true only when both discovery AND vuln testing of the endpoints are done. JSON only:';
  return { messages: [{ role: 'user', content }] };
}

/**
 * Ask the LLM for the next recon step(s). Impure via injected `chat` (defaults to
 * aiProvider.chat). Never throws — on failure it returns `{steps:[], done:true}`
 * so the loop terminates cleanly.
 */
export async function planReconStep(context, { chat, model } = {}) {
  const call = chat || ai.chat;
  try {
    const { messages } = buildReconPrompt(context);
    const reply = await call(messages, model);
    const parsed = safeParse(reply);
    if (!parsed) return { steps: [], done: true };
    return {
      steps: Array.isArray(parsed.steps) ? parsed.steps : [],
      done: !!parsed.done,
    };
  } catch (_) {
    return { steps: [], done: true };
  }
}

function mergeResult(context, result) {
  if (!result || !result.ok) return;
  for (const f of result.findings || []) context.findings.push(f);
  const bucket = SURFACE_BUCKET[result.kind];
  if (bucket && Array.isArray(result.items)) {
    const seen = new Set(
      context.surface[bucket].map((x) =>
        typeof x === 'string' ? x : JSON.stringify(x)
      )
    );
    for (const it of result.items) {
      const key = typeof it === 'string' ? it : JSON.stringify(it);
      if (!seen.has(key)) {
        seen.add(key);
        context.surface[bucket].push(it);
      }
    }
  }
}

/**
 * Run the bounded recon loop. Never throws; never auto-submits.
 * @param {{scope, chat?, agentClient, approve?, model?, policy?, budget?, maxDepth?}} opts
 *   - `approve(call) => bool` gates `active` tools (default: deny → skip).
 * @returns {Promise<{triage, findings, surface, executed, budgetUsed}>}
 */
export async function runReconLoop({
  scope,
  chat,
  agentClient,
  approve,
  model,
  policy = RISK_POLICY,
  budget = DEFAULT_RECON_BUDGET,
  maxDepth = MAX_RECON_DEPTH,
  seeds = [],
  critique,
} = {}) {
  const seedUrls = (Array.isArray(seeds) ? seeds : []).filter(
    (u) => typeof u === 'string' && u.trim()
  );
  const context = {
    scope,
    budget,
    budgetUsed: 0,
    executed: [],
    // Seed known endpoints (with scheme/port) so the planner can target them
    // directly — in-scope hosts alone can't carry a non-standard port/scheme.
    surface: { subdomains: [], urls: [...seedUrls], hosts: [], ports: [] },
    findings: [],
  };
  const executedKeys = new Set();
  const approveFn = typeof approve === 'function' ? approve : async () => false;
  let depth = 0;
  try {
    while (depth < maxDepth && context.budgetUsed < budget) {
      depth++;
      const plan = await planReconStep(context, { chat, model });
      const { steps: proposed } = normalizeReconPlan(plan.steps, {
        scope,
        policy,
        budgetUsed: context.budgetUsed,
        budget,
      });
      // Optional second model vets each step; it may only tighten, never loosen.
      const steps = await applyCritique(proposed, context, critique);
      let ranAny = false;
      for (const d of steps) {
        if (context.budgetUsed >= budget) break;
        if (d.decision === 'deny') {
          context.executed.push({
            decision: 'deny',
            reason: d.reason,
            ran: false,
          });
          continue;
        }
        let go = d.decision === 'allow';
        if (d.decision === 'needs_approval') go = !!(await approveFn(d.call));
        if (!go) {
          context.executed.push({
            decision: d.decision,
            call: d.call,
            reason: d.reason,
            ran: false,
          });
          continue;
        }
        const key = `${d.call.tool}|${d.call.target}|${d.call.profile}`;
        if (executedKeys.has(key)) {
          context.executed.push({
            decision: d.decision,
            call: d.call,
            reason: 'already_run',
            ran: false,
          });
          continue;
        }
        executedKeys.add(key);
        // Deterministic param-targeting: point an injection tool at a discovered
        // param endpoint instead of the bare root, when the target carries no query.
        if (INJECTION_TOOLS.has(d.call.tool) && !/\?.+=/.test(d.call.target || '')) {
          d.call.target = pickInjectionTarget(
            hostOf(d.call.target),
            context.surface.urls,
            d.call.target
          );
        }
        const result = await executeReconTool(d.call, { agentClient });
        context.budgetUsed++;
        ranAny = true;
        mergeResult(context, result);
        context.executed.push({
          decision: d.decision,
          call: d.call,
          ran: true,
          ok: result.ok,
          error: result.error,
          found: (result.findings || []).length,
        });
      }
      if (plan.done) break;
      if (!ranAny && !steps.length) break; // planner proposed nothing runnable
    }
  } catch (_) {
    /* never throw — return what we have */
  }
  // Finalize through the finding-intelligence layer: validate → enrich → rank.
  const t = finalizeTriage(context.findings);
  return {
    triage: t.ranked,
    reportworthy: t.reportworthy,
    summary: t.summary,
    findings: context.findings,
    surface: context.surface,
    executed: context.executed,
    budgetUsed: context.budgetUsed,
  };
}
