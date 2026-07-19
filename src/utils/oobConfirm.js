// OOB / blind confirmation (D1) — pure, unit-testable (no chrome.*/network).
//
// The companion agent's out-of-band collector mints a canary callback URL and
// records any interaction the target's backend makes to it. An interaction on a
// blind candidate (SSRF, blind SQLi/RCE) is hard proof the backend reached out.
// This classifies the agent's polled interactions into a confirmation, and marks
// the finding so the EXISTING validation gate (which already bonuses `oob`
// findings with `oobHit`) scores it as confirmed. Code decides; nothing here runs.

/**
 * Classify polled out-of-band interactions for a canary id. Pure; never throws.
 * @param {object[]} interactions  the agent's recorded interactions for the cid
 * @returns {{confirmed:boolean, hitCount:number, evidence:string}}
 */
export function classifyOobInteractions(interactions, { cid } = {}) {
  const arr = Array.isArray(interactions) ? interactions.filter(Boolean) : [];
  const hitCount = arr.length;
  if (!hitCount) {
    return { confirmed: false, hitCount: 0, evidence: 'no out-of-band interaction yet' };
  }
  const kinds = [...new Set(arr.map((i) => String((i && (i.protocol || i.method || i.kind)) || 'http')))];
  return {
    confirmed: true,
    hitCount,
    evidence: `${hitCount} out-of-band interaction(s) received (${kinds.join('/')}) — blind vulnerability confirmed`,
  };
}

/**
 * Return a NEW finding with the out-of-band result attached. `oobHit` drives the
 * validation gate's oob bonus. Pure; never throws.
 */
export function markOobResult(finding, result) {
  const f = finding && typeof finding === 'object' ? finding : {};
  return {
    ...f,
    oobHit: !!(result && result.confirmed),
    oobHitCount: (result && result.hitCount) || 0,
  };
}
