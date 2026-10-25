// Endpoint harvesting (#6 — SPA/API discovery). Pure, unit-testable.
//
// Modern targets are SPAs: their real API routes (/rest/..., /api/...) live as
// strings inside JS bundles, not in static HTML links — so a plain crawl surfaces
// nothing to test. This mines the raw text a tool already returned (katana/httpx/
// gau output, a fetched JS bundle) for quoted rooted paths and absolute URLs,
// resolves them against the page base, and keeps only the in-scope ones. The loop
// merges the result into its known endpoints so the planner has something to test.
// Pure; never throws.

import { isInScope, hostFromUrl } from './scope';

// Quoted rooted paths: "/rest/products/search", '/api/x?y=1', `/graphql`
const QUOTED_PATH = /['"`](\/[A-Za-z0-9_\-./~]{1,180}(?:\?[^'"`\s]{0,180})?)['"`]/g;
// Absolute URLs embedded in text.
const ABS_URL = /https?:\/\/[A-Za-z0-9.\-]+(?::\d+)?(\/[^\s'"`<>()]{0,200})?/g;
// Static assets we don't want as "endpoints".
const STATIC = /\.(js|mjs|css|map|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|pdf|zip|mp4|woff)(\?|$)/i;

function originOf(base) {
  try {
    const u = new URL(base);
    return `${u.protocol}//${u.host}`;
  } catch (_) {
    return typeof base === 'string' ? base.replace(/\/+$/, '') : '';
  }
}

export function extractEndpoints(text, base, scope) {
  const out = [];
  const seen = new Set();
  if (typeof text !== 'string' || !text) return out;
  const origin = originOf(base);

  const add = (url) => {
    if (!url || seen.has(url) || STATIC.test(url)) return;
    try {
      if (!isInScope(url, scope || { inScope: [], outOfScope: [] })) return;
    } catch (_) { return; }
    seen.add(url);
    out.push(url);
  };

  let m;
  QUOTED_PATH.lastIndex = 0;
  while ((m = QUOTED_PATH.exec(text))) {
    const path = m[1];
    if (/^\/\//.test(path)) continue; // protocol-relative handled by ABS_URL
    if (origin) add(origin + path);
  }
  ABS_URL.lastIndex = 0;
  while ((m = ABS_URL.exec(text))) {
    add(m[0]);
  }
  return out.slice(0, 50); // cap — avoid flooding the surface
}

export { hostFromUrl };
