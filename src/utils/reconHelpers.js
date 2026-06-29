// Pure helpers for active recon URL handling. No network or chrome.* calls, so
// these are fully unit-testable. The background service worker uses them to
// decide what it may fetch.

// Standard files probed during light active recon.
const RECON_FILES = ['/robots.txt', '/sitemap.xml', '/.well-known/security.txt'];

/**
 * Given a page URL or origin, return the list of standard recon-file URLs to
 * GET. Returns [] when the input cannot be parsed.
 */
export function buildReconFileUrls(input) {
  let origin;
  try {
    origin = new URL(input).origin;
  } catch (_) {
    return [];
  }
  return RECON_FILES.map((p) => origin + p);
}

/**
 * Resolve a discovered endpoint (path or absolute URL) against the page URL,
 * returning a same-origin absolute URL string, or null if it is cross-origin
 * or unparseable.
 */
export function normalizeEndpoint(endpoint, pageUrl) {
  if (!endpoint || typeof endpoint !== 'string') return null;
  let resolved;
  try {
    resolved = new URL(endpoint, pageUrl);
  } catch (_) {
    return null;
  }
  if (!isSameOrigin(resolved.href, pageUrl)) return null;
  return resolved.href;
}

/** True when both URLs share scheme + host + port. */
export function isSameOrigin(a, b) {
  try {
    return new URL(a).origin === new URL(b).origin;
  } catch (_) {
    return false;
  }
}

/** Hostname of a URL, or '' if unparseable. */
export function hostFromUrl(url) {
  try {
    return new URL(url).hostname;
  } catch (_) {
    return '';
  }
}

/**
 * Decide whether a host is permitted by the allowlist. '*' permits everything;
 * otherwise an entry matches when it equals the host or is a substring of it
 * (consistent with the existing payloadValidator convention).
 */
export function isHostAllowed(allowlist, host) {
  if (!Array.isArray(allowlist) || !host) return false;
  if (allowlist.includes('*')) return true;
  return allowlist.some((entry) => entry === host || host.includes(entry));
}
