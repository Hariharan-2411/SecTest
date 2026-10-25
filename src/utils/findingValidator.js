// LLM finding-validator (#4) — a false-positive filter that re-checks a finding,
// the finding-level parallel to the step critic. Pure prompt + DI-tested drafter.
//
// RETAIN-ALL: this NEVER drops a finding. It returns a verdict the caller uses to
// quiet ALERTS on likely false positives while keeping every finding stored (lows
// chain into highs). Fail-OPEN: any error/ambiguity → 'likely' (kept, not hidden).

import * as ai from './aiProvider';

const VERDICTS = ['confirmed', 'likely', 'false_positive'];

function clip(v, max = 400) {
  return (typeof v === 'string' ? v : v == null ? '' : String(v)).replace(/\s+/g, ' ').trim().slice(0, max);
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
  try { return JSON.parse(t); } catch (_) { return null; }
}

/** Build the (single user) validation prompt from a finding. Pure. */
export function buildFindingValidationPrompt(finding) {
  const f = finding || {};
  const content =
    'You are a senior bug-bounty triager filtering FALSE POSITIVES from an automated scanner. ' +
    'Given ONE finding and its evidence, judge whether it is a TRUE positive worth a human triager’s time. ' +
    'Be skeptical of generic, low-confidence, or evidence-free signals; do NOT dismiss a finding that has concrete, ' +
    'specific evidence. Return JSON only: {"verdict":"confirmed|likely|false_positive","reason":"<short>"}.\n\n' +
    `Type: ${clip(f.type || f.name || f.title, 60)}\n` +
    `Host: ${clip(f.host || f.target, 120)}\n` +
    `Severity: ${clip(f.severity, 20)}\n` +
    `Confidence: ${f.confidence == null ? '' : f.confidence}\n` +
    `Evidence: ${clip(f.matched || f.evidence, 400) || '(none provided)'}\n\n` +
    'JSON only:';
  return [{ role: 'user', content }];
}

/**
 * Validate one finding. Impure via injected `chat` (defaults to aiProvider.chat).
 * Never throws. Unknown/garbage → 'likely' so the finding is KEPT.
 * @returns {Promise<{verdict:'confirmed'|'likely'|'false_positive', reason:string, source:'llm'|'default'}>}
 */
export async function validateFinding(finding, { chat, model } = {}) {
  const call = chat || ai.chat;
  const keep = { verdict: 'likely', reason: '', source: 'default' };
  try {
    const parsed = safeParse(await call(buildFindingValidationPrompt(finding), model));
    if (!parsed || !VERDICTS.includes(parsed.verdict)) return keep;
    return { verdict: parsed.verdict, reason: clip(parsed.reason, 200), source: 'llm' };
  } catch (_) {
    return keep;
  }
}
