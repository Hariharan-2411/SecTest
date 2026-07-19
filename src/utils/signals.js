// Signal-triggered auto-escalation — pure, unit-testable (no chrome.*/network).
//
// Turns the passive finding stream into a ranked list of "suggested next moves":
// when a high-signal finding is present, surface a one-tap escalation suggestion
// with a one-line reason. Two signal sources, both grounded in real findings:
//   1. CHAIN-LINK (highest): the finding advances a near-complete playbook chain
//      (reuses chainGoals.deriveChainGoals) — the strongest, most specific signal.
//   2. HIGH-SIGNAL TYPE: the finding is a notable class on its own (exposed spec,
//      GraphQL introspection, a secret, an access-control candidate, DOM-XSS,
//      permissive CORS) even when no incomplete chain involves it.
//
// Suggestions only — nothing runs. The UI offers a one-tap Escalate that reuses
// the existing human-triggered escalation flow. Every candidate is scope-checked
// and above the noise band before it can be suggested.

import { evaluateScope } from './scope';
import { canEscalateFinding } from './validate';
import { FINDING_SEVERITIES } from './findings';
import { deriveChainGoals } from './chainGoals';

// High-signal finding types → why it's worth a look + a rank (lower = higher
// priority). Chain-link suggestions always outrank these (rank 0).
const SIGNAL_REASONS = {
  jwt: { reason: 'Exposed credential in a response/JS', rank: 1 },
  aws_access_key: { reason: 'Exposed AWS credential', rank: 1 },
  google_api_key: { reason: 'Exposed Google API key', rank: 1 },
  github_token: { reason: 'Exposed GitHub token', rank: 1 },
  slack_token: { reason: 'Exposed Slack token', rank: 1 },
  stripe_key: { reason: 'Exposed Stripe key', rank: 1 },
  private_key: { reason: 'Exposed private key', rank: 1 },
  'api-spec-exposed': { reason: 'Exposed API spec — a readable OpenAPI/Swagger doc maps new surface', rank: 2 },
  'graphql-introspection': { reason: 'GraphQL introspection enabled — full schema exposed', rank: 2 },
  'api-idor-candidate': { reason: 'Access-control candidate — worth confirming (you verify impact)', rank: 2 },
  'api-auth': { reason: 'Missing-auth candidate — worth confirming', rank: 2 },
  'permissive-cors': { reason: 'Permissive CORS with credentials', rank: 2 },
  'graphql-suggestions': { reason: 'GraphQL field suggestions leak schema', rank: 3 },
  'dom-xss': { reason: 'DOM-XSS sink candidate — confirm reachability', rank: 3 },
};

export const HIGH_SIGNAL_TYPES = new Set(Object.keys(SIGNAL_REASONS));

function hostInScope(host, scope) {
  if (!scope) return true;
  const h = typeof host === 'string' ? host.trim() : '';
  if (!h) return true; // no host to check
  const url = /^https?:\/\//i.test(h) ? h : `https://${h}`;
  return evaluateScope(url, scope).allowed;
}

const sevRank = (s) => {
  const i = FINDING_SEVERITIES.indexOf(s);
  return i === -1 ? FINDING_SEVERITIES.length : i;
};

/**
 * Rank escalation suggestions across a finding set. Pure; never throws.
 *  - a candidate must be escalatable (band >= minBand) AND in scope
 *  - it's suggested if it advances a near-complete chain OR is a high-signal type
 *  - sorted chain-links first, then by signal rank, then severity, then confidence
 * @returns {{findingId,type,title,reason,chainLink:boolean,chainGoals:object[]}[]}
 */
export function detectEscalationSignals(findings, { scope, minBand = 'tentative', max = 5 } = {}) {
  const list = Array.isArray(findings) ? findings.filter(Boolean) : [];
  const out = [];
  for (const f of list) {
    if (!f || !f.id) continue;
    if (!canEscalateFinding(f, { minBand })) continue; // noise/below-band → skip
    if (!hostInScope(f.host, scope)) continue;
    const chainGoals = deriveChainGoals(f, { findings: list, scope });
    const isChainLink = chainGoals.length > 0;
    const signal = SIGNAL_REASONS[f.type];
    if (!isChainLink && !signal) continue;
    const reason = isChainLink
      ? `Advances "${chainGoals[0].name}" — missing ${chainGoals[0].missing.map((m) => m.label).join(', ')}`
      : signal.reason;
    out.push({
      findingId: f.id,
      type: f.type,
      title: typeof f.title === 'string' ? f.title : '',
      reason,
      chainLink: isChainLink,
      chainGoals: isChainLink ? chainGoals : [],
      _rank: isChainLink ? 0 : signal.rank,
      _sev: sevRank(f.severity),
      _conf: typeof f.confidence === 'number' ? f.confidence : 0,
    });
  }
  out.sort((a, b) => a._rank - b._rank || a._sev - b._sev || b._conf - a._conf);
  return out.slice(0, Math.max(0, max)).map(({ _rank, _sev, _conf, ...s }) => s);
}
