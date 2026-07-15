// API / GraphQL injection & access-control candidate analysis — pure, unit-
// testable (no chrome.*/network).
//
// Turns the endpoint maps from apisurface.js (Phase A) into *candidates*:
//   - planParamInjections(): which (GET) params to fuzz with which payload
//     family — the request driver runs these, classifyReflection() scores them.
//   - planAuthReplays() + classifyAuthReplay(): is an auth-observed endpoint
//     still reachable without credentials? (a missing-auth candidate).
//   - detectIdorCandidates(): auth-gated {id} routes worth a manual object-level
//     authorization check.
// buildInjectionFindings() shapes the confirmed candidates into normalized
// Findings that flow through validate -> enrich -> report like every source.
//
// The honest boundary (BUG_BOUNTY_AUTOMATION_PLAN §1): access control and IDOR
// are HUMAN-owned. This surfaces candidates and tags them for review — it never
// asserts a broken-access bug, because only a human knows whose data a 200
// returned. It only ever plans GET requests (read-only); POST/PUT/DELETE are
// never auto-fired.

import { PAYLOADS } from './payloads';
import { normalizeFinding } from './findings';

const DEFAULT_FAMILIES = ['xss', 'sqli'];
const MAX_INJECT_TARGETS = 60;

/**
 * Plan param-injection targets from an API inventory: one representative payload
 * per (param, family) for GET endpoints that have both an example URL and query
 * params. Returns [{ method, path, example, param, family, payload }]. Pure.
 */
export function planParamInjections(inventory, { families, maxTargets = MAX_INJECT_TARGETS } = {}) {
  const fams = (Array.isArray(families) && families.length ? families : DEFAULT_FAMILIES).filter(
    (f) => PAYLOADS[f] && Array.isArray(PAYLOADS[f].payloads) && PAYLOADS[f].payloads.length
  );
  const out = [];
  for (const e of Array.isArray(inventory) ? inventory : []) {
    if (!e || e.method !== 'GET' || !e.example) continue;
    const params = Array.isArray(e.params) ? e.params : [];
    for (const param of params) {
      for (const family of fams) {
        if (out.length >= maxTargets) return out;
        out.push({
          method: 'GET',
          path: e.path,
          example: e.example,
          param,
          family,
          payload: PAYLOADS[family].payloads[0],
        });
      }
    }
  }
  return out;
}

/**
 * Did the payload appear in the injected response but NOT the baseline? That
 * "newly reflected" delta is the reflection evidence (avoids flagging content
 * that was already on the page). Pure.
 */
export function classifyReflection({ baselineBody, injectedBody, payload } = {}) {
  if (typeof payload !== 'string' || !payload) return { reflected: false };
  const base = typeof baselineBody === 'string' ? baselineBody : '';
  const inj = typeof injectedBody === 'string' ? injectedBody : '';
  const reflected = inj.includes(payload) && !base.includes(payload);
  return { reflected };
}

/**
 * GET endpoints observed carrying auth — the request driver re-requests these
 * without credentials to test whether auth is actually enforced. Pure.
 */
export function planAuthReplays(inventory) {
  return (Array.isArray(inventory) ? inventory : []).filter(
    (e) => e && e.method === 'GET' && e.hasAuth && e.example
  ).map((e) => ({ method: 'GET', path: e.path, example: e.example }));
}

// A 2xx status code (200–299).
function is2xx(s) {
  return typeof s === 'number' && s >= 200 && s < 300;
}

/**
 * Compare an authenticated vs anonymous replay of the same endpoint. A
 * missing-auth CANDIDATE needs the anon reply to be 2xx AND similar in size to
 * the authed one (a 401/403, or a very different body, means auth is enforced or
 * the anon path just served something else). Pure.
 */
export function classifyAuthReplay({ authed, anon } = {}) {
  const a = anon || {};
  const b = authed || {};
  if (a.status === 401 || a.status === 403) {
    return { candidate: false, reason: 'enforced' };
  }
  if (!is2xx(a.status) || !is2xx(b.status)) {
    return { candidate: false, reason: 'inconclusive' };
  }
  const la = Number(a.length) || 0;
  const lb = Number(b.length) || 0;
  const ratio = lb === 0 ? (la === 0 ? 1 : 0) : Math.min(la, lb) / Math.max(la, lb);
  if (ratio >= 0.8) {
    return { candidate: true, reason: 'anon reply 2xx with content comparable to authenticated' };
  }
  return { candidate: false, reason: 'different_content' };
}

/** Auth-gated routes with a dynamic {id} segment — object-level authz to check. Pure. */
export function detectIdorCandidates(inventory) {
  return (Array.isArray(inventory) ? inventory : []).filter(
    (e) => e && e.hasAuth && typeof e.path === 'string' && e.path.includes('{id}')
  ).map((e) => ({ method: e.method || 'GET', path: e.path }));
}

/**
 * Shape confirmed candidates into normalized Findings:
 *   - api-injection (medium)        a payload reflected on a param
 *   - api-auth (medium)             endpoint reachable without credentials
 *   - api-idor-candidate (low)      auth-gated {id} route to check manually
 * All land as tentative through the gate (human-owned judgment). Pure.
 */
export function buildInjectionFindings(
  { host = '', injections = [], auth = [], idor = [] } = {},
  now = new Date().toISOString()
) {
  const out = [];
  for (const inj of Array.isArray(injections) ? injections : []) {
    out.push(
      normalizeFinding(
        {
          host,
          type: 'api-injection',
          severity: 'medium',
          title: `Reflected ${inj.family} candidate on "${inj.param}"`,
          evidence: `Payload reflected unmodified in the response for param "${inj.param}" of ${inj.method} ${inj.path}. Verify exploitability manually.`,
          source: 'api-inject',
          ref: inj.example || inj.path,
        },
        now
      )
    );
  }
  for (const a of Array.isArray(auth) ? auth : []) {
    out.push(
      normalizeFinding(
        {
          host,
          type: 'api-auth',
          severity: 'medium',
          title: `Endpoint reachable without authentication: ${a.method} ${a.path}`,
          evidence: `Observed carrying auth in-app, but ${a.reason || 'answered an anonymous request'}. Confirm it returns protected data — access control is a human call.`,
          source: 'api-inject',
          ref: a.example || a.path,
        },
        now
      )
    );
  }
  for (const d of Array.isArray(idor) ? idor : []) {
    out.push(
      normalizeFinding(
        {
          host,
          type: 'api-idor-candidate',
          severity: 'low',
          title: `IDOR worth checking: ${d.method} ${d.path}`,
          evidence: `Auth-gated route with a user-controlled {id}. Manually verify object-level authorization (try another user's id).`,
          source: 'api-inject',
          ref: d.path,
        },
        now
      )
    );
  }
  return out;
}
