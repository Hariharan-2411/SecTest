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
    `Already run: ${done.join(', ') || '(none)'}. ` +
    `Discovered so far: ${(s.subdomains || []).length} subdomains, ${
      (s.hosts || []).length
    } hosts, ${(s.urls || []).length} urls, ${(s.ports || []).length} ports; ${
      (context.findings || []).length
    } findings. ` +
    `Budget remaining: ${remaining} tool runs. ` +
    'Propose the next 1-3 recon steps as JSON only: {"steps":[{"tool","target","profile"}],"done":false}. ' +
    'Reference only in-scope targets and allowed tools. Set done:true when further recon is not worthwhile. JSON only:';
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
} = {}) {
  const context = {
    scope,
    budget,
    budgetUsed: 0,
    executed: [],
    surface: { subdomains: [], urls: [], hosts: [], ports: [] },
    findings: [],
  };
  const executedKeys = new Set();
  const approveFn = typeof approve === 'function' ? approve : async () => false;
  let depth = 0;
  try {
    while (depth < maxDepth && context.budgetUsed < budget) {
      depth++;
      const plan = await planReconStep(context, { chat, model });
      const { steps } = normalizeReconPlan(plan.steps, {
        scope,
        policy,
        budgetUsed: context.budgetUsed,
        budget,
      });
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
