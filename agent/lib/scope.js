// Scope model for the companion agent — mirrors chrome-boiler/src/utils/scope.js
// so the extension and the agent enforce identical rules. Pure, no I/O.
//
// SAFETY: the agent NEVER trusts the client. Every /scan re-checks the target
// against this scope server-side. Out-of-scope always wins.
//
// Pattern semantics (matched against a hostname, case-insensitive):
//   '*'             → every host
//   '*.example.com' → example.com AND any subdomain
//   'example.com'   → that exact host only

'use strict';

const EMPTY_SCOPE = { inScope: [], outOfScope: [] };

/** Extract a bare, lowercased hostname from a URL, host, or host:port/path. */
function hostFromTarget(input) {
  if (!input || typeof input !== 'string') return '';
  let s = input.trim();
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//i, ''); // strip scheme
  s = s.split('/')[0].split('?')[0].split('#')[0]; // strip path/query/frag
  s = s.replace(/:\d+$/, ''); // strip port
  return s.trim().toLowerCase().replace(/\.$/, '');
}

/** Normalize a raw scope entry to a bare host pattern (leading '.' → '*.'). */
function normalizePattern(raw) {
  if (!raw || typeof raw !== 'string') return '';
  let s = raw.trim();
  if (!s || s.startsWith('#') || s.startsWith('//')) return '';
  s = hostFromTarget(s);
  if (s.startsWith('.')) s = '*' + s;
  return s;
}

/** Parse newline/comma-separated scope text into normalized, de-duped patterns. */
function parseScopeText(text) {
  if (!text || typeof text !== 'string') return [];
  const out = [];
  const seen = new Set();
  for (const token of text.split(/[\n,]/)) {
    const p = normalizePattern(token);
    if (p && !seen.has(p)) {
      seen.add(p);
      out.push(p);
    }
  }
  return out;
}

function matchesPattern(hostname, pattern) {
  if (!hostname || !pattern) return false;
  const host = hostname.toLowerCase();
  const pat = pattern.toLowerCase();
  if (pat === '*') return true;
  if (pat.startsWith('*.')) {
    const base = pat.slice(2);
    return host === base || host.endsWith('.' + base);
  }
  return host === pat;
}

function matchesAny(hostname, patterns) {
  return Array.isArray(patterns) && patterns.some((p) => matchesPattern(hostname, p));
}

/**
 * Evaluate a target (URL or bare host) against a scope.
 * @returns {{allowed:boolean, reason:string, host:string}}
 *   reason ∈ 'bad_target' | 'out_of_scope' | 'no_scope' | 'not_in_scope' | 'in_scope'
 */
function evaluateTarget(target, scope = EMPTY_SCOPE) {
  const host = hostFromTarget(target);
  if (!host) return { allowed: false, reason: 'bad_target', host: '' };
  const inScope = (scope && scope.inScope) || [];
  const outOfScope = (scope && scope.outOfScope) || [];
  if (matchesAny(host, outOfScope)) return { allowed: false, reason: 'out_of_scope', host };
  if (inScope.length === 0) return { allowed: false, reason: 'no_scope', host };
  if (matchesAny(host, inScope)) return { allowed: true, reason: 'in_scope', host };
  return { allowed: false, reason: 'not_in_scope', host };
}

function isTargetInScope(target, scope = EMPTY_SCOPE) {
  return evaluateTarget(target, scope).allowed;
}

module.exports = {
  EMPTY_SCOPE,
  hostFromTarget,
  normalizePattern,
  parseScopeText,
  matchesPattern,
  matchesAny,
  evaluateTarget,
  isTargetInScope,
};
