// API surface discovery — pure, unit-testable helpers (no chrome.*/network).
//
// Extends the scanner beyond <form> fields to the REST/JSON surface. Two safe
// sources feed one deduped endpoint inventory:
//   - inventoryFromRequests(): passively observed XHR/fetch requests as you
//     browse, collapsing /users/123 -> /users/{id} so a route counts once.
//   - parseOpenApi(): a readable OpenAPI/Swagger spec, which both maps the whole
//     API and is itself a finding (an exposed spec leaks internal routes).
// buildApiFindings() shapes these into the normalized Finding model so they flow
// through validate -> enrich -> report exactly like every other source.
//
// Analytical only: it records what the app already exposed; it never fetches.

import { extractParamsFromUrls } from './inventory';
import { normalizeFinding } from './findings';

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
const MAX_INVENTORY = 500;

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEXID_RE = /^[0-9a-f]{24,}$/i;

/** True when a path segment looks like a dynamic id (numeric, UUID, long hex). */
function isDynamicSegment(seg) {
  return /^\d+$/.test(seg) || UUID_RE.test(seg) || HEXID_RE.test(seg);
}

/** Path (no host, no query) for a URL or bare path string. '' if unusable. */
function pathOf(u) {
  if (typeof u !== 'string' || !u) return '';
  try {
    return new URL(u).pathname;
  } catch (_) {
    const q = u.indexOf('?');
    const p = q >= 0 ? u.slice(0, q) : u;
    return p.startsWith('/') ? p : `/${p}`;
  }
}

/**
 * Collapse a URL/path to a route template: dynamic segments (numeric ids, UUIDs,
 * long hex) become {id}; host and query string are dropped. Pure.
 */
export function templatizePath(u) {
  const path = pathOf(u);
  if (!path) return '';
  return path
    .split('/')
    .map((seg) => (seg && isDynamicSegment(seg) ? '{id}' : seg))
    .join('/');
}

/**
 * Parse an OpenAPI v3 / Swagger v2 spec into a flat list of
 * { method, path, params } endpoints. Unknown/malformed input yields []. Pure.
 */
export function parseOpenApi(spec) {
  if (!spec || typeof spec !== 'object') return [];
  const paths = spec.paths;
  if (!paths || typeof paths !== 'object' || Array.isArray(paths)) return [];
  const basePath = typeof spec.basePath === 'string' ? spec.basePath : '';
  const out = [];
  for (const [rawPath, item] of Object.entries(paths)) {
    if (!item || typeof item !== 'object') continue;
    const path = `${basePath}${rawPath}`;
    for (const method of METHODS) {
      const op = item[method.toLowerCase()];
      if (!op || typeof op !== 'object') continue;
      const params = Array.isArray(op.parameters)
        ? op.parameters
            .map((p) => p && p.name)
            .filter((n) => typeof n === 'string' && n)
        : [];
      out.push({ method, path, params });
    }
  }
  return out;
}

/** True if an observed request looks like an API call (vs a page/asset load). */
export function isApiEvent(event) {
  if (!event || typeof event.url !== 'string') return false;
  if (event.type === 'xmlhttprequest') return true;
  const path = pathOf(event.url).toLowerCase();
  return (
    /(^|\/)(api|rest|graphql|gql)(\/|$)/.test(path) || path.endsWith('.json')
  );
}

/** Any auth-bearing request header present? */
function hasAuthHeader(headers) {
  if (!Array.isArray(headers)) return false;
  return headers.some(
    (h) => h && /^(authorization|cookie|x-api-key)$/i.test(h.name || '')
  );
}

/**
 * Fold ONE observed request into an endpoint inventory, deduping by method +
 * templated path (unions params, ORs hasAuth, bumps count). Returns a NEW array
 * when it changes; the SAME array (unchanged) for a non-API event or at the
 * route cap. Pure — this is the incremental core `inventoryFromRequests` and the
 * passive background listener both build on.
 */
export function mergeApiEvent(inventory, event) {
  const inv = Array.isArray(inventory) ? inventory : [];
  if (!isApiEvent(event)) return inv;
  const method = String(event.method || 'GET').toUpperCase();
  const path = templatizePath(event.url);
  if (!path) return inv;
  const params = extractParamsFromUrls([event.url]);
  const auth = hasAuthHeader(event.requestHeaders);
  const out = inv.slice();
  const idx = out.findIndex((e) => e.method === method && e.path === path);
  if (idx === -1) {
    if (out.length >= MAX_INVENTORY) return inv; // ceiling on distinct routes
    out.push({
      method,
      path,
      params: params.slice(),
      hasAuth: auth,
      count: 1,
      example: event.url, // first concrete url — a probe target for injection tests
    });
  } else {
    const prev = out[idx];
    const mergedParams = prev.params.slice();
    for (const p of params) if (!mergedParams.includes(p)) mergedParams.push(p);
    out[idx] = {
      ...prev,
      params: mergedParams,
      hasAuth: prev.hasAuth || auth,
      count: (prev.count || 0) + 1,
    };
  }
  return out;
}

/**
 * Fold a batch of observed requests into a deduped endpoint inventory:
 * [{ method, path, params, hasAuth, count }]. Non-API requests are dropped;
 * non-arrays yield []. Pure.
 */
export function inventoryFromRequests(events) {
  let inv = [];
  for (const ev of Array.isArray(events) ? events : []) {
    inv = mergeApiEvent(inv, ev);
  }
  return inv;
}

// Well-known paths where an OpenAPI / Swagger spec is commonly (mis)exposed.
const SPEC_PATHS = [
  '/openapi.json',
  '/swagger.json',
  '/v2/api-docs',
  '/api-docs',
  '/openapi.yaml',
  '/swagger.yaml',
  '/.well-known/openapi.json',
];

/** Absolute candidate spec URLs for a page's origin. []' for a bad url. Pure. */
export function apiSpecCandidates(pageUrl) {
  let origin;
  try {
    origin = new URL(pageUrl).origin;
  } catch (_) {
    return [];
  }
  return SPEC_PATHS.map((p) => origin + p);
}

/**
 * Union parsed OpenAPI endpoints into an existing inventory, deduping by
 * method+path. Spec-only routes are tagged { fromSpec:true, count:0 } and never
 * overwrite an observed route's count. Returns a NEW array. Pure.
 */
export function mergeSpecEndpoints(inventory, endpoints) {
  const out = (Array.isArray(inventory) ? inventory : []).slice();
  const keys = new Set(out.map((e) => `${e.method} ${e.path}`));
  for (const e of Array.isArray(endpoints) ? endpoints : []) {
    if (!e || !e.method || !e.path) continue;
    const k = `${e.method} ${e.path}`;
    if (keys.has(k)) continue;
    keys.add(k);
    out.push({
      method: e.method,
      path: e.path,
      params: Array.isArray(e.params) ? e.params.slice() : [],
      hasAuth: false,
      count: 0,
      fromSpec: true,
    });
  }
  return out;
}

/**
 * Shape discovered API surface into normalized Findings:
 *   - api-spec-exposed (low)          when a readable OpenAPI/Swagger spec exists
 *   - api-surface (informational)     summarizing the observed endpoint inventory
 * Emits nothing when there is neither. Pure.
 */
export function buildApiFindings(
  { host = '', specUrl, specEndpoints = [], inventory = [] } = {},
  now = new Date().toISOString()
) {
  const out = [];
  if (specUrl) {
    const n = Array.isArray(specEndpoints) ? specEndpoints.length : 0;
    out.push(
      normalizeFinding(
        {
          host,
          type: 'api-spec-exposed',
          severity: 'low',
          title: 'API specification publicly readable',
          evidence: `Readable API spec at ${specUrl} exposing ${n} endpoint${
            n === 1 ? '' : 's'
          }.`,
          source: 'api-recon',
          ref: specUrl,
        },
        now
      )
    );
  }
  const inv = Array.isArray(inventory) ? inventory : [];
  if (inv.length) {
    const lines = inv
      .slice(0, 50)
      .map((e) => `${e.method} ${e.path}${e.hasAuth ? ' [auth]' : ''}`)
      .join('\n');
    out.push(
      normalizeFinding(
        {
          host,
          type: 'api-surface',
          severity: 'informational',
          title: `${inv.length} API endpoint${
            inv.length === 1 ? '' : 's'
          } observed`,
          evidence: lines,
          source: 'api-recon',
        },
        now
      )
    );
  }
  return out;
}
