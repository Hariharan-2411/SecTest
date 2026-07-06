// Passive site inventory — pure, unit-testable merge helpers (no chrome.*/network).
//
// As you browse an in-scope target, the content script reports what is already
// in each loaded page (endpoints, links, scripts, forms, cookie names). These
// helpers accumulate those observations into one de-duplicated inventory per
// host, so the attack surface grows as you navigate instead of being a single
// snapshot. Purely passive: it only records what the page already exposed.

// Keep per-host lists bounded so storage stays small.
const CAPS = { endpoints: 1000, links: 1000, params: 500, scripts: 500, forms: 300, cookieNames: 200, pages: 500, secrets: 300, sinks: 500 };

/** A fresh, empty inventory for one host. */
export function emptyInventory() {
  return {
    endpoints: [],
    links: [],
    params: [],
    scripts: [],
    forms: [],
    cookieNames: [],
    pages: [],
    secrets: [],
    sinks: [],
    firstSeen: null,
    updatedAt: null,
  };
}

/** Extract distinct query-param NAMES from a list of URLs (values ignored). */
export function extractParamsFromUrls(urls) {
  const names = new Set();
  for (const u of Array.isArray(urls) ? urls : []) {
    let qs = '';
    try {
      qs = new URL(u).search;
    } catch (_) {
      const i = String(u).indexOf('?');
      qs = i >= 0 ? String(u).slice(i) : '';
    }
    if (!qs) continue;
    for (const pair of qs.replace(/^\?/, '').split('&')) {
      const name = pair.split('=')[0];
      if (name) names.add(decodeURIComponent(name));
    }
  }
  return Array.from(names);
}

function unionCap(existing, incoming, cap, keyOf = (x) => x) {
  const seen = new Set(existing.map(keyOf));
  const out = existing.slice(0, cap);
  for (const item of Array.isArray(incoming) ? incoming : []) {
    if (out.length >= cap) break; // check BEFORE pushing — strict ceiling
    if (item == null) continue;
    const k = keyOf(item);
    if (!seen.has(k)) {
      seen.add(k);
      out.push(item);
    }
  }
  return out;
}

/**
 * Merge one page observation into an inventory, returning a NEW inventory.
 * @param {object} inv    existing inventory (or falsy → starts empty)
 * @param {object} obs    { pageUrl, endpoints, links, scripts, forms, cookieNames }
 * @param {string} [now]  ISO timestamp (injectable for tests)
 */
export function mergeObservation(inv, obs = {}, now = new Date().toISOString()) {
  const base = inv && typeof inv === 'object' ? inv : emptyInventory();
  const cur = { ...emptyInventory(), ...base };

  const endpoints = obs.endpoints || [];
  const links = obs.links || [];
  const paramUrls = [...endpoints, ...links];

  const next = {
    endpoints: unionCap(cur.endpoints, endpoints, CAPS.endpoints),
    links: unionCap(cur.links, links, CAPS.links),
    params: unionCap(cur.params, extractParamsFromUrls(paramUrls), CAPS.params),
    scripts: unionCap(cur.scripts, obs.scripts, CAPS.scripts),
    forms: unionCap(cur.forms, obs.forms, CAPS.forms, (f) => `${(f.method || 'get').toLowerCase()} ${f.action || ''}`),
    cookieNames: unionCap(cur.cookieNames, obs.cookieNames, CAPS.cookieNames),
    pages: unionCap(cur.pages, obs.pageUrl ? [obs.pageUrl] : [], CAPS.pages),
    secrets: unionCap(cur.secrets, obs.secrets, CAPS.secrets, (s) => `${s.type}:${s.preview}`),
    sinks: unionCap(cur.sinks, obs.sinks, CAPS.sinks, (s) => `${s.sink}:${s.snippet}`),
    firstSeen: cur.firstSeen || now,
    updatedAt: now,
  };
  return next;
}

/** Counts for a compact UI summary. */
export function summarizeInventory(inv) {
  const i = { ...emptyInventory(), ...(inv || {}) };
  return {
    endpoints: i.endpoints.length,
    links: i.links.length,
    params: i.params.length,
    scripts: i.scripts.length,
    forms: i.forms.length,
    cookieNames: i.cookieNames.length,
    pages: i.pages.length,
    secrets: i.secrets.length,
    sinks: i.sinks.length,
    updatedAt: i.updatedAt,
  };
}
