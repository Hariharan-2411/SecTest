// Chain playbooks — canonical exploit-chain templates + a DETERMINISTIC matcher.
//
// The matcher maps the real finding set onto known chain shapes, reporting which
// links are present and which are MISSING. No LLM in this path: templates are
// static declarative data and matching is pure code. Same eligibility gates as
// chains.normalizeChain (in scope + confidence >= tentative). Consumed by
// chains.js to ground the LLM and to emit complete chains without an LLM call.

import { evaluateScope } from './scope';
import { sortFindings, deriveSeverity } from './findings';
import { BANDS, scoreFinding } from './validate';

/**
 * Each link's `match.types` is an any-of list of finding.type values. Every type
 * below is one the codebase emits today (taint/injection/graphql/websocket/oracle/
 * apisurface/headers/secrets), so seeds match real findings. A link whose types
 * don't exist yet simply never matches — safe to add forward-looking playbooks.
 */
export const PLAYBOOKS = [
  {
    id: 'xss-secret-ato',
    name: 'DOM-XSS → exposed token → account takeover',
    impact: 'Client-side code execution plus a retrievable credential enables session/account takeover.',
    severity: 'critical',
    links: [
      { id: 'xss', label: 'DOM-XSS sink reachable', match: { types: ['dom-xss'] } },
      {
        id: 'token',
        label: 'Exposed token/secret',
        match: { types: ['jwt', 'aws_access_key', 'google_api_key', 'github_token', 'slack_token', 'stripe_key', 'private_key'] },
      },
    ],
  },
  {
    id: 'cors-cookie-theft',
    name: 'Permissive CORS + credentialed cookie → cross-origin data theft',
    impact: 'A credentialed wildcard CORS policy lets a malicious origin read authenticated responses.',
    severity: 'high',
    links: [
      { id: 'cors', label: 'Permissive CORS with credentials', match: { types: ['permissive-cors'] } },
      { id: 'cookie', label: 'Cookie set on the response', match: { types: ['set-cookie'] } },
    ],
  },
  {
    id: 'graphql-introspection-idor',
    name: 'GraphQL introspection → surface → access-control candidate',
    impact: 'A fully mapped GraphQL schema plus a missing-authorization candidate points to object-level access-control abuse.',
    severity: 'high',
    links: [
      { id: 'introspection', label: 'Introspection/suggestions enabled', match: { types: ['graphql-introspection', 'graphql-suggestions'] } },
      { id: 'surface', label: 'Query/mutation surface mapped', match: { types: ['graphql-surface'] } },
      { id: 'authz', label: 'Access-control candidate', match: { types: ['api-idor-candidate', 'api-auth'] } },
    ],
  },
  {
    id: 'api-injection-idor',
    name: 'API/SQL injection + missing-auth/IDOR → data compromise',
    impact: 'An injectable parameter alongside a broken access-control candidate compounds into data compromise.',
    severity: 'critical',
    links: [
      { id: 'injection', label: 'Injection candidate', match: { types: ['api-injection', 'sqli-boolean'] } },
      { id: 'access', label: 'Access-control candidate', match: { types: ['api-idor-candidate', 'api-auth'] } },
    ],
  },
  {
    id: 'cswsh-ws-injection',
    name: 'CSWSH + WebSocket injection → cross-origin action',
    impact: 'A cross-site WebSocket hijack plus an injectable frame lets an attacker drive authenticated socket actions.',
    severity: 'high',
    links: [
      { id: 'cswsh', label: 'Cross-site WebSocket hijack candidate', match: { types: ['ws-cswsh'] } },
      { id: 'wsinj', label: 'WebSocket frame injection candidate', match: { types: ['ws-injection'] } },
    ],
  },
  {
    id: 'spec-injection',
    name: 'Exposed API spec → injectable endpoint',
    impact: 'A readable OpenAPI/Swagger spec maps the surface that an injection candidate then exploits.',
    severity: 'high',
    links: [
      { id: 'spec', label: 'Exposed API spec', match: { types: ['api-spec-exposed'] } },
      { id: 'injection', label: 'Injection/IDOR candidate', match: { types: ['api-injection', 'sqli-boolean', 'api-idor-candidate'] } },
    ],
  },
  {
    id: 'xss-weak-csp',
    name: 'DOM-XSS + missing/weak CSP → reliable exploitation',
    impact: 'A weak or absent CSP removes the mitigation that would otherwise blunt the DOM-XSS.',
    severity: 'high',
    links: [
      { id: 'xss', label: 'DOM-XSS sink reachable', match: { types: ['dom-xss'] } },
      { id: 'csp', label: 'Missing/weak CSP', match: { types: ['missing-csp', 'weak-csp'] } },
    ],
  },
];

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'informational'];

function str(v) {
  return typeof v === 'string' ? v : v == null ? '' : String(v);
}

function getConfidence(f) {
  return typeof f.confidence === 'number' ? f.confidence : scoreFinding(f).confidence;
}

function hostInScope(host, scope) {
  if (!scope) return true;
  const h = str(host).trim();
  if (!h) return true; // no host to check
  const url = /^https?:\/\//i.test(h) ? h : `https://${h}`;
  return evaluateScope(url, scope).allowed;
}

// Eligible to fill ANY link: in scope AND not noise-band. Mirrors chains.js gates.
function isEligible(f, scope) {
  if (!f) return false;
  if (!hostInScope(f.host, scope)) return false;
  return getConfidence(f) >= BANDS.tentative;
}

function linkMatches(link, finding) {
  const types = link && link.match && Array.isArray(link.match.types) ? link.match.types : [];
  return types.includes(finding.type);
}

// Greedy match of ONE playbook against already-eligible, strongest-first findings.
function matchOne(playbook, eligibleSorted) {
  const links = Array.isArray(playbook.links) ? playbook.links : [];
  const satisfied = [];
  const filledLinkIds = new Set();
  const usedFindingIds = new Set();
  for (const finding of eligibleSorted) {
    if (usedFindingIds.has(finding.id)) continue;
    for (const link of links) {
      if (filledLinkIds.has(link.id)) continue;
      if (linkMatches(link, finding)) {
        satisfied.push({ linkId: link.id, findingId: finding.id, type: finding.type });
        filledLinkIds.add(link.id);
        usedFindingIds.add(finding.id);
        break; // this finding fills at most one link
      }
    }
  }
  const missing = links
    .filter((l) => !filledLinkIds.has(l.id))
    .map((l) => ({ linkId: l.id, label: str(l.label), match: l.match }));
  const constituents = satisfied.map((s) => eligibleSorted.find((f) => f.id === s.findingId));
  return {
    playbookId: playbook.id,
    name: playbook.name,
    satisfied,
    missing,
    completeness: links.length ? satisfied.length / links.length : 0,
    complete: links.length > 0 && satisfied.length === links.length,
    severity: deriveSeverity(constituents),
  };
}

/**
 * Match every playbook against the finding set. Pure; never throws.
 * Returns only playbooks with >= 1 satisfied link, sorted complete-first, then
 * completeness desc, then severity (critical first).
 */
export function matchPlaybooks(findings, { scope } = {}) {
  const arr = Array.isArray(findings) ? findings.filter(Boolean) : [];
  const eligibleSorted = sortFindings(arr.filter((f) => isEligible(f, scope)));
  const results = [];
  for (const pb of PLAYBOOKS) {
    const m = matchOne(pb, eligibleSorted);
    if (m.satisfied.length >= 1) results.push(m);
  }
  const sevRank = (s) => {
    const i = SEVERITY_ORDER.indexOf(s);
    return i === -1 ? SEVERITY_ORDER.length : i;
  };
  results.sort(
    (a, b) =>
      Number(b.complete) - Number(a.complete) ||
      b.completeness - a.completeness ||
      sevRank(a.severity) - sevRank(b.severity)
  );
  return results;
}
