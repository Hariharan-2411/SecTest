// Runtime DOM-XSS confirmation (B2) — pure descriptor + classifier.
//
// SAFETY CONTRACT: the model is NOT involved here. This constructs a DATA
// descriptor (a unique benign canary + which whitelisted source to set + which
// sink to watch) from a static DOM-XSS candidate. A fixed MAIN-world runner
// interprets the descriptor against a whitelist and NEVER evaluates any code from
// it — it sets the canary at the source, observes whether it reaches the DOM/sink,
// then restores. Canary-only: it checks REACHABILITY, never fires exploit code.
// classifyProbeResult turns the runner's observation into a confirmation; the
// validation gate (probeConfirmed bonus) then raises confidence. Nothing runs here.

// Whitelisted canary sources (controllable inputs) and dangerous sink types.
export const PROBE_SOURCES = ['location.hash', 'window.name'];
export const PROBE_SINKS = ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval', 'setTimeout'];

let _seq = 0;
function canaryToken() {
  _seq = (_seq + 1) % 1e9;
  return `IRIS_CANARY_${Date.now().toString(36)}_${_seq}`;
}

function normSink(sink) {
  const s = String(sink || '').toLowerCase();
  if (s.includes('innerhtml')) return 'innerHTML';
  if (s.includes('outerhtml')) return 'outerHTML';
  if (s.includes('insertadjacent')) return 'insertAdjacentHTML';
  if (s.includes('document.write') || s.includes('.write')) return 'document.write';
  if (s.includes('eval')) return 'eval';
  if (s.includes('settimeout') || s.includes('setinterval')) return 'setTimeout';
  return null;
}

function normSource(sources) {
  const arr = Array.isArray(sources) ? sources.map((x) => String(x).toLowerCase()) : [];
  if (arr.some((s) => s.includes('hash'))) return 'location.hash';
  if (arr.some((s) => s.includes('name'))) return 'window.name';
  if (arr.some((s) => s.includes('search') || s.includes('location') || s.includes('url') || s.includes('referrer')))
    return 'location.hash';
  return null;
}

/**
 * Build a runtime-probe DATA descriptor from a DOM-XSS finding. Pure; returns null
 * when the finding lacks a supported sink or source. Never contains code.
 * @returns {{canary:string, source:string, sink:string, findingId:string|null}|null}
 */
export function buildDomProbe(finding) {
  if (!finding || finding.type !== 'dom-xss') return null;
  const sink = normSink(finding.sink);
  const source = normSource(finding.sources);
  if (!sink || !source) return null;
  return { canary: canaryToken(), source, sink, findingId: finding.id || null };
}

/**
 * Classify a MAIN-world probe observation. Pure; never throws.
 * @param {{reachedSink?:boolean, unescaped?:boolean, sinkType?:string, source?:string}} result
 * @returns {{confirmed:boolean, evidence:string}}
 */
export function classifyProbeResult(result, { canary } = {}) {
  const r = result && typeof result === 'object' ? result : {};
  if (r.reachedSink && r.unescaped) {
    return { confirmed: true, evidence: `canary reached ${r.sinkType || 'the DOM'} unescaped from ${r.source || 'the source'}` };
  }
  if (r.reachedSink) {
    return { confirmed: false, evidence: `canary reached ${r.sinkType || 'the DOM'} but was escaped/encoded` };
  }
  return { confirmed: false, evidence: 'canary did not reach the sink' };
}
