// Chain narrative + impact framing (J1) — pure prompt + DI-testable drafter.
//
// Groq drafts the business-impact prose for a VALIDATED chain (each step is a
// real, in-scope finding). The CODE owns severity — the model never sets it; it
// only narrates (summary / impact / remediation) and may propose a CVSS vector
// that is kept as a validated LABEL. Same posture as validateProse: the model
// rephrases, it does not decide. Never throws.

import { validateCvss } from './chains';
import * as ai from './aiProvider';

function str(v, max = 400) {
  return typeof v === 'string' ? v.slice(0, max) : v == null ? '' : String(v).slice(0, max);
}
function clip(v, max = 400) {
  return str(v, max).replace(/\s+/g, ' ').trim();
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

/** Build the (single user) narrative prompt from a validated chain. Pure. */
export function buildChainNarrativePrompt(chain) {
  const c = chain || {};
  const steps = (Array.isArray(c.steps) ? c.steps : []).map((s) => str(s && s.type, 40)).join(' → ');
  const hosts = Array.isArray(c.hosts) ? c.hosts.join(', ') : '';
  const content =
    'You are a penetration tester writing the IMPACT section of a bug-bounty report for a VALIDATED ' +
    'exploit chain — every step below is a real, confirmed, in-scope finding. Write concise, credible ' +
    'business-impact prose for a triager. Do NOT invent steps or findings beyond those listed, and do ' +
    'NOT overstate. The severity is authoritative and set by the tool — do NOT change it. ' +
    'Return JSON only: {"summary":"<1-2 sentences>","impact":"<realistic business impact>",' +
    '"remediation":"<concrete fix>","cvss":"<CVSS:3.1/... vector or empty>"}.\n\n' +
    `Chain: ${clip(c.title, 160)}\n` +
    `Severity (authoritative, do not change): ${str(c.severity, 20)}\n` +
    `Steps: ${steps}\n` +
    (hosts ? `Hosts: ${clip(hosts, 200)}\n` : '') +
    (c.rationale ? `Why plausible: ${clip(c.rationale, 240)}\n` : '') +
    '\nJSON only:';
  return [{ role: 'user', content }];
}

/**
 * Draft the impact narrative for a validated chain. Impure via injected `chat`
 * (defaults to aiProvider.chat). Never throws. The returned `severity` is ALWAYS
 * the chain's own — the model cannot move it.
 * @returns {Promise<{source:'llm'|'error', summary:string, impact:string, remediation:string, cvss:string|null, severity:string}>}
 */
export async function draftChainNarrative(chain, { chat, model } = {}) {
  const c = chain || {};
  const severity = c.severity || 'informational';
  const fail = { source: 'error', summary: '', impact: '', remediation: '', cvss: null, severity };
  if (!Array.isArray(c.steps) || c.steps.length < 2) return fail;
  const call = chat || ai.chat;
  try {
    const reply = await call(buildChainNarrativePrompt(c), model);
    const parsed = safeParse(reply);
    if (!parsed) return fail;
    return {
      source: 'llm',
      summary: clip(parsed.summary, 400),
      impact: clip(parsed.impact, 500),
      remediation: clip(parsed.remediation, 400),
      // Model CVSS is kept only as a validated display label; the chain's own
      // aiCvss is the fallback. Severity is never taken from the model.
      cvss: validateCvss(parsed.cvss) || c.aiCvss || null,
      severity,
    };
  } catch (_) {
    return fail;
  }
}
