// Chain-directed escalation goals — pure, unit-testable (no chrome.*/network).
//
// Composes chainPlaybooks.matchPlaybooks with the escalation pipeline: when the
// finding being escalated is a satisfied link in a NEAR-COMPLETE playbook, the
// MISSING link becomes an escalation GOAL. The AI planner receives these goals as
// grounding and plans toward them; every step it returns still passes through
// escalation.normalizePlan (allow-list + server-side scope re-check). Code derives
// the goals; the model only narrates a plan to reach them.

import { matchPlaybooks } from './chainPlaybooks';

// Missing finding-type -> which EXISTING escalation verb(s) tend to produce it, and
// a one-line how. Advisory only. `verbs` are ACTION_VERBS keys; run_payload's
// family is named in `note` (families live in escalation.VULN_FAMILIES).
export const LINK_PROBE_HINTS = {
  'dom-xss': { verbs: ['confirm_reflection', 'run_payload'], note: 'drive a marker into the sink; confirm reflection/execution (run_payload family: xss)' },
  jwt: { verbs: ['deep_js'], note: 'deep-scan JS/responses for an exposed credential' },
  aws_access_key: { verbs: ['deep_js'], note: 'deep-scan JS/responses for an exposed credential' },
  google_api_key: { verbs: ['deep_js'], note: 'deep-scan JS/responses for an exposed credential' },
  github_token: { verbs: ['deep_js'], note: 'deep-scan JS/responses for an exposed credential' },
  slack_token: { verbs: ['deep_js'], note: 'deep-scan JS/responses for an exposed credential' },
  stripe_key: { verbs: ['deep_js'], note: 'deep-scan JS/responses for an exposed credential' },
  private_key: { verbs: ['deep_js'], note: 'deep-scan JS/responses for an exposed credential' },
  'sqli-boolean': { verbs: ['differential_probe'], note: 'boolean/timing differential to confirm blind SQLi' },
  'api-injection': { verbs: ['differential_probe'], note: 'differential probe on the candidate parameter' },
  'api-idor-candidate': { verbs: ['probe_endpoint'], note: 'GET-only replay (neighbor id / no-auth) — human verifies' },
  'api-auth': { verbs: ['probe_endpoint'], note: 'GET-only no-auth replay to test missing authorization' },
  'graphql-introspection': { verbs: ['probe_endpoint'], note: 'probe the GraphQL endpoint for introspection' },
  'graphql-suggestions': { verbs: ['probe_endpoint'], note: 'probe the GraphQL endpoint for field suggestions' },
  'graphql-surface': { verbs: ['probe_endpoint'], note: 'enumerate the GraphQL query/mutation surface' },
  'api-spec-exposed': { verbs: ['probe_endpoint'], note: 'fetch the OpenAPI/Swagger spec' },
  'permissive-cors': { verbs: ['probe_endpoint'], note: 'observe response CORS headers' },
  'set-cookie': { verbs: ['probe_endpoint'], note: 'observe Set-Cookie flags on an authenticated response' },
  'missing-csp': { verbs: ['manual'], note: 'review the CSP header by hand' },
  'weak-csp': { verbs: ['manual'], note: 'review the CSP header by hand' },
  'ws-cswsh': { verbs: ['manual'], note: 'assess cross-site WebSocket hijack by hand' },
  'ws-injection': { verbs: ['manual'], note: 'test WebSocket frame injection by hand' },
};

const DEFAULT_HINT = { verbs: ['manual'], note: 'assess by hand' };

// First matching hint across a link's any-of types, else the manual fallback.
function hintForTypes(types) {
  for (const t of Array.isArray(types) ? types : []) {
    if (LINK_PROBE_HINTS[t]) return LINK_PROBE_HINTS[t];
  }
  return DEFAULT_HINT;
}

/**
 * Derive up to `max` chain goals for the finding being escalated. Pure; never throws.
 *  - runs matchPlaybooks (inherits its scope + tentative-band eligibility gates)
 *  - keeps playbooks where THIS finding fills a link AND >= 1 link is still missing
 *  - matchPlaybooks already orders partial matches closest-to-complete first
 * @returns {{playbookId,name,have:string[],missing:{linkId,label,types:string[],hint:{verbs:string[],note:string}}[]}[]}
 */
export function deriveChainGoals(finding, { findings, scope, max = 3 } = {}) {
  if (!finding || typeof finding.type !== 'string' || !finding.id) return [];
  const list = Array.isArray(findings) ? findings : [];
  const matches = matchPlaybooks(list, { scope });
  const goals = [];
  for (const m of matches) {
    if (!Array.isArray(m.missing) || m.missing.length === 0) continue; // complete -> skip
    const fills =
      Array.isArray(m.satisfied) && m.satisfied.some((s) => s.findingId === finding.id);
    if (!fills) continue; // this finding isn't a link in the chain
    goals.push({
      playbookId: m.playbookId,
      name: m.name,
      have: m.satisfied.map((s) => s.type),
      missing: m.missing.map((x) => ({
        linkId: x.linkId,
        label: x.label,
        types: (x.match && x.match.types) || [],
        hint: hintForTypes(x.match && x.match.types),
      })),
    });
    if (goals.length >= max) break;
  }
  return goals;
}
