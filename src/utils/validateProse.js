// LLM justification-prose adapter — turns a validation verdict into a one-sentence
// "why this confidence" explanation. IMPURE by default (calls aiProvider.chat),
// but the LLM call is injectable so the orchestrator is testable without network.
//
// This is the NARRATION layer only. The confidence number and band are computed
// by the gate (utils/validate.js) and are authoritative — this module never
// changes them and never parses a number back out of the model's text. Mirrors
// escalation.js: the model advises phrasing, the code owns the facts.
//
//   • buildProsePrompt / fallbackProse / sanitizeProse — pure, deterministic.
//   • explainConfidence — thin orchestrator; tries the (injected) LLM, sanitizes
//     the reply, and degrades to fallbackProse on empty/garbage/too-long/throw.
//     It NEVER throws.

import * as ai from './aiProvider';

const DEFAULT_MAX_LEN = 240;

function cap(s) {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
}

/**
 * Deterministic offline sentence from a validation verdict. Never throws.
 * @param {{confidence:number, band:string, reasons:string[]}} validation
 * @returns {string}
 */
export function fallbackProse(validation) {
  if (!validation || typeof validation.confidence !== 'number') {
    return 'Unscored: no validation available.';
  }
  const band = cap(validation.band || 'unrated');
  const head = `${band} (${validation.confidence}%)`;
  const reasons = Array.isArray(validation.reasons)
    ? validation.reasons.filter(Boolean)
    : [];
  if (!reasons.length) return `${head}: scored from available evidence.`;
  return `${head}: ${reasons.join('; ')}.`;
}

/**
 * Collapse text to a single trimmed line; reject empty or over-length output
 * (returns '' so the caller can fall back). Pure.
 */
export function sanitizeProse(text, { maxLen = DEFAULT_MAX_LEN } = {}) {
  if (typeof text !== 'string') return '';
  const one = text.replace(/\s+/g, ' ').trim();
  if (!one || one.length > maxLen) return '';
  return one;
}

/**
 * Build the (single user) chat message that grounds the model in the reasons and
 * instructs a rephrase-only, one-sentence answer. Pure. Uses only the
 * user/assistant contract the chat proxy documents.
 */
export function buildProsePrompt(finding, validation) {
  const type = (finding && finding.type) || 'finding';
  const reasons =
    validation && Array.isArray(validation.reasons)
      ? validation.reasons.filter(Boolean)
      : [];
  const bullets = reasons.length
    ? reasons.map((r) => `- ${r}`).join('\n')
    : '- (no specific signals)';
  const content =
    'You are explaining a web security-testing finding to a human tester. ' +
    'Rephrase the reasons below into ONE plain-English sentence. Add no new claims, ' +
    'do not mention or change any confidence score or severity, and do not use markdown.\n\n' +
    `Finding type: ${type}\nReasons:\n${bullets}\n\nOne sentence only:`;
  return { messages: [{ role: 'user', content }] };
}

/**
 * Explain a finding's confidence in one sentence. Tries the injected LLM, then
 * degrades to the deterministic fallback. Never throws.
 * @returns {Promise<{prose:string, source:'llm'|'fallback'}>}
 */
export async function explainConfidence(
  finding,
  validation,
  { chat, model } = {}
) {
  const call = chat || ai.chat;
  try {
    const { messages } = buildProsePrompt(finding, validation);
    const reply = await call(messages, model);
    const prose = sanitizeProse(reply);
    if (prose) return { prose, source: 'llm' };
  } catch (_) {
    // fall through to the deterministic fallback
  }
  return { prose: fallbackProse(validation), source: 'fallback' };
}
