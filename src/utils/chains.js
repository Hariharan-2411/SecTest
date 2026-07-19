// Chain hypotheses — propose exploit chains across the finding set, then VALIDATE
// every proposal against the real findings + scope before anything is shown.
//
// The pure layer (normalizeChains/deriveSeverity/validateCvss/buildChainsPrompt)
// is the SAFETY CONTRACT between the model and the UI — same posture as
// escalation.js: the LLM hypothesizes, the code decides what's grounded.
//
// GUARANTEES (enforced here, never trusted from the model):
//   • Every step must reference a REAL finding (by id, fallback ref); invented
//     steps are dropped. A chain left with < 2 grounded steps is rejected.
//   • Each grounded finding's host is re-checked against scope.
//   • Noise-band findings (confidence < tentative) can't be chain links.
//   • `step.type` is copied from the real finding, never the model's claim.
//   • Severity is DERIVED deterministically; the model's severity is ignored and
//     its CVSS is kept only as a validated display label.
//   • Chain count and step count are capped; overflow is rejected, not run.
//
// Nothing executes. proposeChains (impure via injected chat) is DI-testable and
// never throws — any failure yields zero chains.

import { evaluateScope } from './scope';
import { sortFindings, deriveSeverity } from './findings';
import { BANDS, scoreFinding, validateFindings } from './validate';
import * as ai from './aiProvider';
import { PLAYBOOKS, matchPlaybooks } from './chainPlaybooks';

export { deriveSeverity };

export const MAX_CHAINS = 8;
export const MAX_STEPS = 6;
export const MAX_CONTEXT_FINDINGS = 30;
const MAX_RATIONALE = 240;

let _seq = 0;
function chainId() {
  _seq = (_seq + 1) % 1e9;
  return `chn_${Date.now().toString(36)}_${_seq}`;
}

function str(v) {
  return typeof v === 'string' ? v : v == null ? '' : String(v);
}

// Collapse whitespace to a single line and truncate (advisory text, so truncate
// rather than reject).
function clip(s, max) {
  const t = str(s).replace(/\s+/g, ' ').trim();
  return t.length > max ? t.slice(0, max) : t;
}

function getConfidence(f) {
  return typeof f.confidence === 'number'
    ? f.confidence
    : scoreFinding(f).confidence;
}

function hostInScope(host, scope) {
  if (!scope) return true;
  const h = str(host).trim();
  if (!h) return true; // no host to check
  const url = /^https?:\/\//i.test(h) ? h : `https://${h}`;
  return evaluateScope(url, scope).allowed;
}

/** Keep a CVSS 3.1 vector string as a display label, or null. Format-check only. */
export function validateCvss(v) {
  const s = str(v).trim();
  return s && s.length <= 120 && /^CVSS:3\.1\//.test(s) ? s : null;
}

// Validate ONE raw chain against the real findings. Returns { chain } or
// { rejected: { raw, reason } }.
function normalizeChain(raw, { findingsById, scope }) {
  const rawSteps = Array.isArray(raw && raw.steps) ? raw.steps : [];
  const steps = [];
  const constituents = [];
  for (const s of rawSteps.slice(0, MAX_STEPS)) {
    const ref = str(s && (s.findingId != null ? s.findingId : s.ref));
    const finding = findingsById.get(ref);
    if (!finding) continue; // invented -> drop
    if (!hostInScope(finding.host, scope)) continue; // out of scope -> drop
    if (getConfidence(finding) < BANDS.tentative) continue; // noise -> drop
    steps.push({
      findingId: finding.id,
      type: finding.type,
      note: clip(s && s.note, 200),
    });
    constituents.push(finding);
  }
  if (steps.length < 2)
    return { rejected: { raw, reason: 'insufficient_grounded_steps' } };
  return {
    chain: {
      id: chainId(),
      title:
        clip(raw && raw.title, 120) || steps.map((s) => s.type).join(' → '),
      steps,
      findingIds: steps.map((s) => s.findingId),
      severity: deriveSeverity(constituents),
      aiCvss: validateCvss(raw && raw.cvss),
      rationale: clip(raw && raw.rationale, MAX_RATIONALE),
    },
  };
}

/**
 * Validate the LLM's raw chain plan against the real findings + scope. Pure.
 * @param {{chains:object[]}|object[]} rawPlan
 * @returns {{chains:object[], rejected:{raw:object,reason:string}[]}}
 */
export function normalizeChains(rawPlan, { findings, scope } = {}) {
  const findingsById = new Map();
  for (const f of Array.isArray(findings) ? findings : []) {
    if (!f) continue;
    if (f.id != null) findingsById.set(String(f.id), f);
    if (f.ref && !findingsById.has(String(f.ref)))
      findingsById.set(String(f.ref), f);
  }
  const list = Array.isArray(rawPlan)
    ? rawPlan
    : Array.isArray(rawPlan && rawPlan.chains)
    ? rawPlan.chains
    : [];
  const chains = [];
  const rejected = [];
  for (const raw of list) {
    if (chains.length >= MAX_CHAINS) {
      rejected.push({ raw, reason: 'over_cap' });
      continue;
    }
    const res = normalizeChain(raw, { findingsById, scope });
    if (res.chain) chains.push(res.chain);
    else rejected.push(res.rejected);
  }
  return { chains, rejected };
}

/**
 * Build the (single user) prompt that grounds the model in a bounded slice of the
 * finding set and asks for JSON chains referencing finding ids only. Pure.
 */
export function buildChainsPrompt(findings, { playbookMatches } = {}) {
  const top = sortFindings(Array.isArray(findings) ? findings : []).slice(
    0,
    MAX_CONTEXT_FINDINGS
  );
  const lines = top.map(
    (f) =>
      `- id=${str(f.id)} type=${str(f.type)} severity=${str(
        f.severity
      )} confidence=${getConfidence(f)} host=${str(f.host)} title=${clip(
        f.title,
        80
      )}`
  );
  const partial = (Array.isArray(playbookMatches) ? playbookMatches : []).filter(
    (m) => m && m.complete === false
  );
  let grounding = '';
  if (partial.length) {
    const pbLines = partial
      .slice(0, MAX_CHAINS)
      .map(
        (m) =>
          `- ${clip(m.name, 120)}: have [${(m.satisfied || [])
            .map((s) => s.linkId)
            .join(', ')}], missing [${(m.missing || [])
            .map((x) => x.linkId)
            .join(', ')}]`
      );
    grounding =
      '\n\nKnown chain patterns partially matched (prefer chains that complete the MISSING links):\n' +
      pbLines.join('\n');
  }
  const content =
    'You are a web application penetration tester reviewing already-discovered, in-scope findings. ' +
    'Propose plausible EXPLOIT CHAINS that combine two or more of these findings into higher impact ' +
    '(e.g. SSRF -> cloud metadata -> IAM keys; XSS -> cookie theft -> account takeover; IDOR -> privilege escalation). ' +
    'Reference ONLY the finding ids listed below — do not invent findings. Each chain needs at least two steps. ' +
    'Return JSON only: {"chains":[{"title","steps":[{"findingId","note"}],"cvss","rationale"}]}.\n\n' +
    `Findings:\n${lines.join('\n') || '- (none)'}` +
    grounding +
    '\n\nJSON only:';
  return { messages: [{ role: 'user', content }] };
}

// Pull a JSON object out of a model reply, tolerating ```json fences and stray prose.
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

// Collapse chains that rest on the same finding-id set (order-insensitive), so an
// LLM proposal duplicating a deterministic playbook chain is shown once. First wins.
function dedupeChains(chains) {
  const seen = new Set();
  const out = [];
  for (const c of Array.isArray(chains) ? chains : []) {
    const key = [...(Array.isArray(c.findingIds) ? c.findingIds : [])].sort().join('|');
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(c);
  }
  return out;
}

/**
 * Ask the model for exploit chains, then validate them. Impure via the injected
 * `chat` (defaults to aiProvider.chat). Never throws.
 * @returns {Promise<{chains:object[], rejected:object[], source:'llm'|'playbook'|'error'}>}
 */
export async function proposeChains(findings, { chat, model, scope } = {}) {
  const call = chat || ai.chat;
  const validated = validateFindings(findings);
  const matches = matchPlaybooks(validated, { scope });
  const partial = matches.filter((m) => !m.complete);
  const pbById = new Map(PLAYBOOKS.map((p) => [p.id, p]));
  // Complete playbook matches -> raw chains, validated by the SAME normalizeChains.
  const deterministicRaw = matches
    .filter((m) => m.complete)
    .map((m) => ({
      title: m.name,
      steps: m.satisfied.map((s) => ({ findingId: s.findingId, note: '' })),
      rationale: (pbById.get(m.playbookId) || {}).impact || '',
      cvss: null,
    }));

  let llmOk = false;
  let llmRaw = [];
  try {
    const { messages } = buildChainsPrompt(validated, { playbookMatches: partial });
    const reply = await call(messages, model);
    const parsed = safeParse(reply);
    if (parsed) {
      llmOk = true;
      llmRaw = Array.isArray(parsed)
        ? parsed
        : Array.isArray(parsed.chains)
        ? parsed.chains
        : [];
    }
  } catch (_) {
    llmOk = false;
  }

  // Deterministic first so they win de-duplication over an identical LLM proposal.
  const { chains, rejected } = normalizeChains([...deterministicRaw, ...llmRaw], {
    findings: validated,
    scope,
  });
  const deduped = dedupeChains(chains);
  // `source` reflects whether the model reply parsed, not chain provenance — a
  // complete playbook still emits its (deterministic) chain even when source is 'llm'.
  const source = llmOk ? 'llm' : deduped.length ? 'playbook' : 'error';
  return { chains: deduped, rejected, source };
}
