// Escalation context assembly — pure, unit-testable (no chrome.*/network).
//
// Builds the COMPACT, BOUNDED snapshot the AI planner sees: the finding plus the
// slice of already-mapped attack surface that's relevant to it (endpoints,
// params, forms, related findings). Bounded on purpose — it keeps the prompt
// cheap and, crucially, GROUNDS the planner in surface we actually observed so
// it proposes tests against real in-scope endpoints, not invented ones.
//
// Analytical only: it selects and trims existing data. It fetches nothing and
// never includes secret VALUES (only their type) or raw page bodies.

const CAPS = { endpoints: 30, params: 30, forms: 10, secrets: 10, cookieNames: 30, related: 10, frameworks: 8 };

function str(v, max = 400) {
  return typeof v === 'string' ? v.slice(0, max) : '';
}

// Try to recover a param name from a finding (oracle findings carry it in the
// title/evidence like `on "id"`); returns '' when none is evident.
export function paramHint(finding = {}) {
  if (typeof finding.param === 'string' && finding.param) return finding.param;
  const m = String(finding.title || finding.evidence || '').match(/["']([A-Za-z0-9_.\-]{1,40})["']/);
  return m ? m[1] : '';
}

/**
 * Rank endpoints by relevance to the finding: those mentioning the param first,
 * then those with a query string, then the rest. Pure; returns a new array.
 */
export function pickRelevantEndpoints(endpoints, param) {
  const arr = (Array.isArray(endpoints) ? endpoints : []).filter((e) => typeof e === 'string');
  const score = (e) => {
    if (param && e.includes(param)) return 0;
    if (e.includes('?')) return 1;
    return 2;
  };
  return arr
    .map((e, i) => ({ e, i, s: score(e) }))
    .sort((a, b) => a.s - b.s || a.i - b.i) // stable within a score band
    .map((x) => x.e);
}

/**
 * Assemble the bounded planner context.
 * @param {object} finding   the finding being escalated
 * @param {{inventory?:object, findings?:object[], recon?:object}} sources
 * @returns compact object safe to send to the model
 */
export function assembleContext(finding = {}, { inventory = {}, findings = [], recon = null, chainGoals = null } = {}) {
  const param = paramHint(finding);

  const f = {
    type: finding.type || 'finding',
    severity: finding.severity || 'medium',
    title: str(finding.title, 200),
    evidence: str(finding.evidence, 500),
    ref: str(finding.ref, 40),
  };
  if (finding.sink) f.sink = str(finding.sink, 60);
  if (Array.isArray(finding.sources)) f.sources = finding.sources.slice(0, 6);
  if (param) f.param = param;

  const inv = inventory || {};
  const inventoryCtx = {
    endpoints: pickRelevantEndpoints(inv.endpoints, param).slice(0, CAPS.endpoints),
    params: (inv.params || []).slice(0, CAPS.params),
    forms: (inv.forms || []).slice(0, CAPS.forms).map((fm) => ({
      method: (fm && fm.method) || 'get',
      action: str(fm && fm.action, 300),
      fieldCount: (fm && fm.fieldCount) || 0,
    })),
    // TYPE ONLY — never send secret values (even masked) into a prompt.
    secrets: (inv.secrets || []).slice(0, CAPS.secrets).map((s) => ({ type: (s && s.type) || 'secret' })),
    cookieNames: (inv.cookieNames || []).slice(0, CAPS.cookieNames),
  };

  const relatedFindings = (Array.isArray(findings) ? findings : [])
    .filter((x) => x && x.id !== finding.id)
    .slice(0, CAPS.related)
    .map((x) => ({ type: x.type, severity: x.severity, title: str(x.title, 120) }));

  const reconMini = recon
    ? { title: str(recon.title, 120), frameworks: (recon.frameworks || []).slice(0, CAPS.frameworks) }
    : undefined;

  return {
    host: str(finding.host, 200),
    finding: f,
    // Placed BEFORE inventory so the highest-value grounding survives the proxy's
    // context clamp. Only present when there's a real goal to hunt.
    ...(Array.isArray(chainGoals) && chainGoals.length ? { chainGoals } : {}),
    inventory: inventoryCtx,
    relatedFindings,
    ...(reconMini ? { recon: reconMini } : {}),
  };
}
