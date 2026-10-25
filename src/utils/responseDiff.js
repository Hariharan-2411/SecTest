// AI response-diff reasoning (F1) — IDOR / logic CANDIDATE drafting.
//
// Two requests to the same endpoint differing only by an object id / authorization
// (your id vs a neighbor's, authed vs not) produce two responses. A deterministic
// diff decides whether they diverge in a way worth a look; if so, the LLM DRAFTS a
// hypothesis (IDOR / logic / benign) with a rationale. This is the bug class the
// plan marks human-owned: the model proposes a CANDIDATE, the human judges intent
// and impact. Never claims a confirmed bug.
//
// PRIVACY GUARDRAIL: raw response bodies (which may hold another user's data) are
// NEVER sent to the model — only metadata (status, length, identical-flag).

import * as ai from './aiProvider';

function str(v, max = 300) {
  return typeof v === 'string' ? v.slice(0, max) : v == null ? '' : String(v).slice(0, max);
}
function clip(v, max = 300) {
  return str(v, max).replace(/\s+/g, ' ').trim();
}
function clamp(n, lo = 0, hi = 100) {
  return Math.max(lo, Math.min(hi, Number.isFinite(n) ? n : 0));
}
function safeParse(text) {
  if (typeof text !== 'string') return null;
  let t = text.trim();
  const fence = t.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence) t = fence[1].trim();
  if (!t.startsWith('{')) {
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
 * Structured, metadata-only diff of two responses. Accepts either `{ status, body }`
 * or the real replay shape `{ status, length }` (bodies are never required — the
 * replay flow captures only status + length). Pure; never throws.
 */
export function diffResponses(a, b) {
  const ra = a && typeof a === 'object' ? a : {};
  const rb = b && typeof b === 'object' ? b : {};
  const hasBodyA = typeof ra.body === 'string';
  const hasBodyB = typeof rb.body === 'string';
  const bodyA = hasBodyA ? ra.body : '';
  const bodyB = hasBodyB ? rb.body : '';
  const statusA = Number(ra.status) || 0;
  const statusB = Number(rb.status) || 0;
  const lenA = typeof ra.length === 'number' ? ra.length : bodyA.length;
  const lenB = typeof rb.length === 'number' ? rb.length : bodyB.length;
  const bothBodies = hasBodyA && hasBodyB;
  const identicalBody = bothBodies && bodyA === bodyB;
  const lenDelta = Math.abs(lenA - lenB);
  // "Divergent" abstracts over both shapes: known-different bodies, or (length
  // only) different lengths. This is the IDOR/logic tell.
  const divergent = bothBodies ? !identicalBody : lenDelta > 0;
  return {
    statusA,
    statusB,
    sameStatus: statusA === statusB,
    lenA,
    lenB,
    lenDelta,
    identicalBody,
    divergent,
    bothOk: statusA >= 200 && statusA < 400 && statusB >= 200 && statusB < 400,
  };
}

/**
 * Worth asking the model about. The tell depends on what varied between requests:
 *   - 'id'   (default): both 2xx AND diverging content → another user's data (IDOR)
 *   - 'auth': both 2xx at all → the anonymous request reached an auth-gated route
 *             (missing auth), whether the content is similar or not.
 */
export function looksInteresting(diff, variant = 'id') {
  const d = diff || {};
  if (!d.bothOk) return false;
  if (variant === 'auth') return true;
  return !!d.divergent;
}

/** Build the (metadata-only) prompt. Pure. Raw bodies are never included. */
export function buildAccessControlPrompt(diff, context = {}, variant = 'id') {
  const d = diff || {};
  const varied =
    variant === 'auth'
      ? 'authorization only (authenticated request vs anonymous / no credentials)'
      : 'an object identifier only (your own id vs another id)';
  const content =
    'You are assisting an AUTHORIZED penetration tester. Two requests were sent to the same endpoint ' +
    `differing by ${varied}. Judge whether the response outcome suggests BROKEN ACCESS CONTROL (IDOR or ` +
    'missing authorization) ' +
    'or a business-logic flaw — or is benign (a proper denial, or identical public data). This is a ' +
    'CANDIDATE for a human to verify; never claim certainty. ' +
    'Return JSON only: {"candidate":true|false,"kind":"idor"|"logic"|"none","confidence":0-100,"rationale":"<1-2 sentences>"}.\n\n' +
    `Endpoint: ${clip(context.endpoint, 200)}\n` +
    `Response A (baseline): status=${d.statusA} body-length=${d.lenA}\n` +
    `Response B (altered id/auth): status=${d.statusB} body-length=${d.lenB}\n` +
    `Both 2xx/3xx: ${d.bothOk}; responses diverge: ${d.divergent}; length delta: ${d.lenDelta}\n\n` +
    'JSON only:';
  return [{ role: 'user', content }];
}

/**
 * Analyze two responses into an access-control CANDIDATE. Impure via injected
 * `chat` (defaults to aiProvider.chat). Never throws. Deterministic short-circuit
 * when the responses don't diverge — no LLM call, no body ever sent.
 * @returns {Promise<{candidate:boolean, kind:'idor'|'logic'|'none', confidence:number, rationale:string, diff:object, source:'deterministic'|'llm'|'error'}>}
 */
export async function analyzeAccessControl({ a, b, variant = 'id', context, chat, model } = {}) {
  const diff = diffResponses(a, b);
  if (!looksInteresting(diff, variant)) {
    return {
      candidate: false,
      kind: 'none',
      confidence: 0,
      rationale: 'responses do not diverge in a way that suggests access-control issues',
      diff,
      source: 'deterministic',
    };
  }
  const call = chat || ai.chat;
  try {
    const messages = buildAccessControlPrompt(diff, context || {}, variant);
    const reply = await call(messages, model);
    const parsed = safeParse(reply);
    if (!parsed) {
      return { candidate: false, kind: 'none', confidence: 0, rationale: 'analysis returned no result', diff, source: 'error' };
    }
    const kind = ['idor', 'logic', 'none'].includes(parsed.kind) ? parsed.kind : 'none';
    const confidence = clamp(Math.round(Number(parsed.confidence)));
    return {
      candidate: !!parsed.candidate && kind !== 'none',
      kind,
      confidence,
      rationale: clip(parsed.rationale, 300),
      diff,
      source: 'llm',
    };
  } catch (_) {
    return { candidate: false, kind: 'none', confidence: 0, rationale: 'analysis unavailable', diff, source: 'error' };
  }
}
