// Response oracles — pure, unit-testable (no chrome.*/network).
//
// Confirmation by differential/timing analysis: send controlled request variants
// and let the RESPONSES decide whether input reaches a backend sink. A boolean
// pair (…AND 1=1 vs …AND 1=2) that yields materially different responses, or a
// sleep payload that measurably delays the response, is far stronger evidence
// than a single reflected payload. This module only compares response summaries;
// the background worker issues the (scope-gated, rate-limited) GETs.
//
// Analytical only: it does math on {status, length, timeMs} triples.

// Benign, well-known confirmation pairs. Boolean pairs are non-destructive
// (they read, never write). Provided as presets; the operator can override.
export const DIFFERENTIAL_PRESETS = {
  sqli_string: { label: 'SQLi (string)', truthy: "' AND '1'='1", falsy: "' AND '1'='2" },
  sqli_numeric: { label: 'SQLi (numeric)', truthy: ' AND 1=1', falsy: ' AND 1=2' },
};

/**
 * Compare two response summaries.
 * @param {{status:number,length:number,timeMs:number}} a
 * @param {{status:number,length:number,timeMs:number}} b
 * @returns {{differs:boolean, signals:{statusDelta:number,lengthDelta:number,timeDelta:number}}}
 */
export function compareResponses(a, b, { lengthThreshold = 40 } = {}) {
  if (!a || !b) return { differs: false, signals: { statusDelta: 0, lengthDelta: 0, timeDelta: 0 } };
  const statusDelta = (a.status || 0) - (b.status || 0);
  const lengthDelta = (a.length || 0) - (b.length || 0);
  const timeDelta = (a.timeMs || 0) - (b.timeMs || 0);
  const differs = statusDelta !== 0 || Math.abs(lengthDelta) >= lengthThreshold;
  return { differs, signals: { statusDelta, lengthDelta, timeDelta } };
}

/**
 * Classify a boolean-differential triple. Strongest signal: the truthy variant
 * mirrors the baseline while the falsy variant diverges (classic boolean SQLi).
 * @param {{base?, truthy, falsy}} r  response summaries
 * @returns {{signal:'boolean'|'none', confidence:number, detail:string}}
 */
export function classifyDifferential({ base, truthy, falsy } = {}, opts = {}) {
  const tf = compareResponses(truthy, falsy, opts);
  if (!tf.differs) {
    return { signal: 'none', confidence: 0, detail: 'truthy and falsy responses are equivalent' };
  }
  let confidence = 0.5;
  let detail = 'truthy vs falsy responses differ';
  if (base) {
    const tb = compareResponses(truthy, base, opts);
    const fb = compareResponses(falsy, base, opts);
    // Truthy ~ base AND falsy ≠ base is the textbook boolean-injection shape.
    if (!tb.differs && fb.differs) {
      confidence = 0.8;
      detail = 'truthy matches baseline, falsy diverges — boolean-injection shape';
    }
  }
  return { signal: 'boolean', confidence, detail };
}

/**
 * Classify a timing pair: a delayed variant whose response time exceeds the
 * baseline by at least `timeThreshold` ms (and is itself that slow) signals a
 * time-based backend evaluation.
 * @returns {{signal:'time'|'none', confidence:number, detail:string}}
 */
export function classifyTiming({ base, delayed } = {}, { timeThreshold = 2500 } = {}) {
  if (!base || !delayed) return { signal: 'none', confidence: 0, detail: 'missing samples' };
  const delta = (delayed.timeMs || 0) - (base.timeMs || 0);
  if (delta >= timeThreshold && (delayed.timeMs || 0) >= timeThreshold) {
    const confidence = delta >= timeThreshold * 1.6 ? 0.85 : 0.65;
    return { signal: 'time', confidence, detail: `delayed response +${delta}ms over baseline` };
  }
  return { signal: 'none', confidence: 0, detail: `delay ${delta}ms below threshold` };
}

/** Current value of a query param in a URL, or '' when absent/unparseable. */
export function paramValue(url, param) {
  try {
    return new URL(url).searchParams.get(param) || '';
  } catch (_) {
    return '';
  }
}

/**
 * Return `url` with `param` set to `value` (added if absent). Pure — never
 * mutates its input. Used to build differential request variants.
 */
export function buildVariantUrl(url, param, value) {
  try {
    const u = new URL(url);
    u.searchParams.set(param, value);
    return u.href;
  } catch (_) {
    return url;
  }
}

/** First query-param name in a URL, or '' when there are none. */
export function firstParam(url) {
  try {
    const it = new URL(url).searchParams.keys().next();
    return it.done ? '' : it.value;
  } catch (_) {
    return '';
  }
}
