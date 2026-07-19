// Payload memory (B4) — pure, unit-testable (no chrome.*/network).
//
// A cross-session "what worked" store: winning payloads keyed by the target's
// framework + sink + vuln class, so Iris sharpens on the stacks you keep hitting.
// Recalled payloads seed future generation (grounding); confirmed DOM-XSS findings
// separately flow into the attack graph (Item A) and chain-directed escalation,
// so B4's graph wire is already satisfied by the finding pipeline. Pure; never
// throws; all mutators return a NEW memory object.

const CAP_PER_KEY = 20;

function str(v) {
  return typeof v === 'string' ? v : v == null ? '' : String(v);
}

/** Stable, case-insensitive key from framework + sink + vulnerability. */
export function memoryKey(context) {
  const c = context && typeof context === 'object' ? context : {};
  return [c.framework || 'any', c.sink || 'any', c.vulnerability || c.vuln || 'any']
    .map((x) => str(x).toLowerCase() || 'any')
    .join('|');
}

/**
 * Record a winning payload under its context key. Returns a NEW memory object.
 * Re-recording the same payload bumps its count. Blank payloads are ignored.
 */
export function recordSuccess(memory, context, payload, { max = CAP_PER_KEY } = {}) {
  const mem = memory && typeof memory === 'object' ? { ...memory } : {};
  const p = str(payload).trim();
  if (!p) return mem;
  const key = memoryKey(context);
  const bucket = Array.isArray(mem[key]) ? mem[key].map((e) => ({ ...e })) : [];
  const existing = bucket.find((e) => e.payload === p);
  if (existing) {
    existing.count = (existing.count || 1) + 1;
    existing.at = Date.now();
  } else {
    bucket.push({ payload: p, count: 1, at: Date.now() });
  }
  bucket.sort((a, b) => (b.count || 0) - (a.count || 0) || (b.at || 0) - (a.at || 0));
  mem[key] = bucket.slice(0, max);
  return mem;
}

/** Recall up to `limit` winning payloads for a context, most-used first. Pure. */
export function recallPayloads(memory, context, { limit = 5 } = {}) {
  const mem = memory && typeof memory === 'object' ? memory : {};
  const bucket = Array.isArray(mem[memoryKey(context)]) ? mem[memoryKey(context)] : [];
  return bucket.slice(0, limit).map((e) => e.payload);
}
