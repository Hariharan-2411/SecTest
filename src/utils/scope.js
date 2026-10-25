// Program-scope model — pure and unit-testable (no chrome.* / network).
//
// A scope is `{ inScope: string[], outOfScope: string[] }` of host patterns.
// Everything the extension does is gated on `isInScope(url, scope)` so a single
// source of truth decides what is allowed. Out-of-scope always wins.
//
// SAFETY: scope enforcement is the core guardrail. Only ever act on targets that
// are explicitly in-scope for a program you are authorized to test.
//
// Pattern semantics (matched against a URL's hostname, case-insensitive):
//   '*'                → matches every host (wildcard-all; the permissive default)
//   '*.example.com'    → example.com AND any subdomain (app.example.com, a.b.example.com)
//   '.example.com'     → alias for '*.example.com'
//   'example.com'      → that exact host only (no subdomains)
//   'admin.example.com'→ that exact host only
// Use `*.x.com` for wildcards and a bare host for an exact match. This lets an
// out-of-scope entry like `admin.example.com` precisely carve a hole out of an
// in-scope `*.example.com`.

export const EMPTY_SCOPE = { inScope: [], outOfScope: [] };

/** Hostname of a URL, or '' if unparseable. */
export function hostFromUrl(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch (_) {
    return '';
  }
}

/**
 * Normalize a raw scope entry to a bare host pattern: strip scheme, path, port,
 * whitespace and a trailing dot; lowercase. A leading '.' becomes '*.'.
 * Returns '' for empty/comment input.
 */
export function normalizePattern(raw) {
  if (!raw || typeof raw !== 'string') return '';
  let s = raw.trim();
  if (!s || s.startsWith('#') || s.startsWith('//')) return '';
  // Drop a scheme if present so "https://x.com/path" → "x.com/path".
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
  // Drop path/query/fragment.
  s = s.split('/')[0].split('?')[0].split('#')[0];
  // Drop a port.
  s = s.replace(/:\d+$/, '');
  s = s.trim().toLowerCase().replace(/\.$/, '');
  if (s.startsWith('.')) s = '*' + s; // ".example.com" → "*.example.com"
  return s;
}

/**
 * Parse a free-text scope list (newline- or comma-separated) into normalized,
 * de-duplicated patterns. Blank lines and `#`/`//` comments are ignored.
 */
export function parseScopeText(text) {
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

/** Does a single hostname match a single pattern? */
export function matchesPattern(hostname, pattern) {
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

/** True when the host matches ANY pattern in the list. */
export function matchesAny(hostname, patterns) {
  return Array.isArray(patterns) && patterns.some((p) => matchesPattern(hostname, p));
}

/**
 * Full evaluation with a reason, for UI messaging.
 * @returns {{allowed:boolean, reason:string, host:string}}
 *   reason ∈ 'bad_url' | 'out_of_scope' | 'no_scope' | 'not_in_scope' | 'in_scope'
 */
export function evaluateScope(url, scope = EMPTY_SCOPE) {
  const host = hostFromUrl(url);
  if (!host) return { allowed: false, reason: 'bad_url', host: '' };
  const inScope = (scope && scope.inScope) || [];
  const outOfScope = (scope && scope.outOfScope) || [];
  if (matchesAny(host, outOfScope)) return { allowed: false, reason: 'out_of_scope', host };
  if (inScope.length === 0) return { allowed: false, reason: 'no_scope', host };
  if (matchesAny(host, inScope)) return { allowed: true, reason: 'in_scope', host };
  return { allowed: false, reason: 'not_in_scope', host };
}

/** Boolean convenience wrapper over `evaluateScope`. */
export function isInScope(url, scope = EMPTY_SCOPE) {
  return evaluateScope(url, scope).allowed;
}

/**
 * Translate a scope's in-scope host patterns into Chrome match patterns for
 * `chrome.scripting.registerContentScripts` / `webRequest` filters.
 *
 * This is what keeps the extension off every tab: content scripts are no longer
 * declared statically for `<all_urls>` in the manifest, they are registered at
 * runtime ONLY for these patterns. An empty in-scope list yields `[]`, which the
 * caller must treat as "register nothing" — the extension stays inert until the
 * operator names a target.
 *
 *   '*'              → ['http://*\/*', 'https://*\/*']  (explicit wildcard only)
 *   '*.example.com'  → ['*://*.example.com/*']  (Chrome's *. also covers the apex)
 *   'example.com'    → ['*://example.com/*']
 *
 * `outOfScope` cannot be expressed as a match pattern (there is no negative
 * form), so carve-outs stay enforced at message time by `evaluateScope`.
 */
export function toMatchPatterns(scope) {
  const inScope = (scope && scope.inScope) || [];
  const out = [];
  const seen = new Set();
  for (const raw of inScope) {
    const p = normalizePattern(raw);
    if (!p) continue;
    const patterns = p === '*' ? ['http://*/*', 'https://*/*'] : [`*://${p}/*`];
    for (const m of patterns) {
      if (!seen.has(m)) {
        seen.add(m);
        out.push(m);
      }
    }
  }
  return out;
}

/**
 * Migration: derive a scope from the legacy flat `allowlist`. '*' stays '*';
 * other entries become `*.entry` to preserve the old substring-ish matching.
 */
export function scopeFromAllowlist(allowlist) {
  const inScope = [];
  const seen = new Set();
  for (const entry of Array.isArray(allowlist) ? allowlist : []) {
    const p = entry === '*' ? '*' : normalizePattern(entry.startsWith('*') ? entry : `*.${entry}`);
    if (p && !seen.has(p)) {
      seen.add(p);
      inScope.push(p);
    }
  }
  // Fail CLOSED: an absent/empty allowlist yields an empty scope, not '*'.
  // `evaluateScope` then returns 'no_scope' and nothing attaches or acts.
  return { inScope, outOfScope: [] };
}
