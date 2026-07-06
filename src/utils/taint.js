// DOM-XSS taint candidates — pure, unit-testable (no chrome.*/network).
//
// Phase A's sink mapper (sinks.js) already records each DOM sink together with
// any controllable source found near it. This module promotes the *tainted*
// ones (a source within reach of a sink) into normalized candidate findings,
// ranked by confidence, so a human can review the highest-risk ones first.
//
// It NEVER claims a confirmed bug: DOM-XSS needs manual verification. Every
// finding is a "review this" pointer with a confidence score, not a verdict.
// The finding shape matches the unified Finding model (findings.js, Phase E) so
// it can be folded in without transformation.

// Sinks where a tainted string most directly becomes executable markup/code.
const HIGH_DANGER_SINKS = new Set([
  'eval',
  'Function',
  'document.write',
  'innerHTML',
  'outerHTML',
  'insertAdjacentHTML',
  'setTimeout(string)',
  'jquery.html',
]);

// Sources an attacker controls most directly (URL/referrer/name/postMessage).
const DIRECT_SOURCES = new Set(['location', 'referrer', 'window.name', 'postMessage']);

function round2(n) {
  return Math.round(n * 100) / 100;
}

/** Stable-ish id for a candidate so repeated derivations dedupe cleanly. */
function candidateId(sink, snippet) {
  return `dom-xss:${sink}:${String(snippet || '').slice(0, 80)}`;
}

/**
 * Turn one mapped sink into a candidate finding, or null when it isn't tainted
 * (no controllable source near it — not worth flagging on its own).
 */
export function sinkToCandidate(entry, host = '') {
  if (!entry || !Array.isArray(entry.sources) || entry.sources.length === 0) return null;

  const sink = entry.sink;
  const highDanger = HIGH_DANGER_SINKS.has(sink);
  const hasDirectSource = entry.sources.some((s) => DIRECT_SOURCES.has(s));

  const danger = highDanger ? 0.6 : 0.4;
  const srcBoost = hasDirectSource ? 0.3 : 0.15;
  const confidence = round2(Math.min(0.95, danger + srcBoost));
  // Candidates are unconfirmed by design — cap at 'medium', never auto-high.
  const severity = highDanger && hasDirectSource ? 'medium' : 'low';

  return {
    id: candidateId(sink, entry.snippet),
    host,
    type: 'dom-xss',
    severity,
    confidence,
    title: `Possible DOM-XSS: ${entry.sources.join('/')} → ${sink}`,
    evidence: entry.snippet || '',
    source: 'sink-analysis',
    ref: 'CWE-79',
    sink,
    sources: entry.sources.slice(),
    line: entry.line,
  };
}

/**
 * Derive ranked DOM-XSS candidate findings from a list of mapped sinks.
 * Deduped by id, sorted by confidence (desc). Pure — takes the sinks already in
 * the inventory and returns findings; stores nothing.
 */
export function taintFindings(sinks, host = '') {
  const byId = new Map();
  for (const entry of Array.isArray(sinks) ? sinks : []) {
    const cand = sinkToCandidate(entry, host);
    if (cand && !byId.has(cand.id)) byId.set(cand.id, cand);
  }
  return Array.from(byId.values()).sort((a, b) => b.confidence - a.confidence);
}

export { HIGH_DANGER_SINKS, DIRECT_SOURCES };
