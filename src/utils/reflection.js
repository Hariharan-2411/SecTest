// Reflection-context classification — pure, unit-testable (no chrome.*/network).
//
// After a unique benign marker is injected into a field, the content script
// re-reads the page and asks: did the marker come back, and in WHAT context?
// Context is what turns "reflected" into an actionable XSS signal — a marker in
// a JS string or an HTML attribute is far more dangerous than one shown as
// plain body text. This module is the pure classifier; the DOM read lives in
// the content script.
//
// Analytical only: it inspects a string you already have. It changes nothing.

/**
 * Classify the context of the marker at position `idx` within serialized HTML.
 * @returns {'js'|'attribute'|'html-body'}
 */
function contextAt(html, lower, idx) {
  // Inside a <script> … </script> block?
  const openScript = lower.lastIndexOf('<script', idx);
  if (openScript !== -1) {
    const closeScript = lower.indexOf('</script', openScript);
    if (closeScript === -1 || closeScript > idx) return 'js';
  }
  // Inside a tag (last '<' after the last '>') → attribute context.
  const lastLt = html.lastIndexOf('<', idx);
  const lastGt = html.lastIndexOf('>', idx);
  if (lastLt > lastGt) return 'attribute';
  return 'html-body';
}

/**
 * Find every occurrence of `marker` in serialized HTML and classify each.
 * @returns {{contexts: string[], count: number}} distinct contexts + total hits.
 */
export function classifyReflection(html, marker) {
  if (!html || !marker || typeof html !== 'string') return { contexts: [], count: 0 };
  const lower = html.toLowerCase();
  const contexts = new Set();
  let count = 0;
  let idx = html.indexOf(marker);
  while (idx !== -1) {
    count++;
    contexts.add(contextAt(html, lower, idx));
    idx = html.indexOf(marker, idx + marker.length);
  }
  return { contexts: Array.from(contexts), count };
}

/**
 * Combine a serialized-HTML classification with an optional URL reflection
 * (checked separately by the caller, since the URL isn't part of the DOM string).
 * @returns {{reflected:boolean, contexts:string[], count:number}}
 */
export function summarizeReflection(html, marker, { urlReflected = false } = {}) {
  const { contexts, count } = classifyReflection(html, marker);
  const all = urlReflected ? Array.from(new Set([...contexts, 'url'])) : contexts;
  return { reflected: all.length > 0, contexts: all, count };
}

/** Generate a unique, benign, easily-searchable marker token. */
export function makeMarker() {
  return 'zqx' + Math.random().toString(36).slice(2, 9) + 'rfl';
}
