// WebSocket surface discovery — pure, unit-testable helpers (no chrome.*/network).
//
// A WebSocket is attack surface a form scanner never sees. Two safe signals map it:
//   - the handshake (observed via webRequest): its Origin + whether it carried
//     cookies tells us if the channel is ambient-cookie-authenticated — the
//     precondition for Cross-Site WebSocket Hijacking (CSWSH).
//   - the frames (observed via a MAIN-world WebSocket shim): the messages the
//     page exchanges, so a human can see the protocol and (manually) fuzz it.
// buildWsFindings() shapes these into the normalized Finding model so they flow
// through validate -> enrich -> report like every other source.
//
// The honest boundary: CSWSH is reported as a CANDIDATE (cookie-authed socket,
// verify the server checks Origin) — it is never auto-exploited, and frames are
// never auto-replayed. mutateFrame() is provided for a human-driven fuzz step.

import { normalizeFinding } from './findings';

/** Host for a ws://, wss://, http:// or https:// URL. '' if unparseable. */
function hostOf(u) {
  try {
    const s = String(u).replace(/^wss:/i, 'https:').replace(/^ws:/i, 'http:');
    return new URL(s).host;
  } catch (_) {
    return '';
  }
}

/** Value of a named header from a webRequest header array (case-insensitive). */
function headerVal(headers, name) {
  const lc = name.toLowerCase();
  const h = (Array.isArray(headers) ? headers : []).find(
    (x) => x && typeof x.name === 'string' && x.name.toLowerCase() === lc
  );
  return h && typeof h.value === 'string' ? h.value : '';
}

/**
 * Analyze a WebSocket handshake observation ({ url, requestHeaders }) into
 * { url, host, origin, hasCookie, sameOrigin }. Pure.
 */
export function analyzeHandshake(details) {
  const url = details && typeof details.url === 'string' ? details.url : '';
  const headers = details && details.requestHeaders;
  const origin = headerVal(headers, 'origin');
  const hasCookie = !!headerVal(headers, 'cookie');
  const host = hostOf(url);
  const originHost = origin ? hostOf(origin) : '';
  return { url, host, origin, hasCookie, sameOrigin: !!host && originHost === host };
}

/**
 * A CSWSH candidate is an ambient-cookie-authenticated socket whose auth is NOT
 * pinned to a per-connection token in the URL (a token can't be forged
 * cross-site; a cookie is sent automatically). Pure heuristic — a human still
 * confirms the server fails to validate Origin.
 */
export function isCswshCandidate(handshake) {
  if (!handshake || !handshake.hasCookie) return false;
  const url = typeof handshake.url === 'string' ? handshake.url : '';
  if (/[?&](token|access_token|auth|api[_-]?key|jwt|sig|signature)=/i.test(url)) {
    return false;
  }
  return true;
}

/**
 * Merge one handshake into a per-host endpoint list, deduped by url and carrying
 * the derived cswsh flag. Returns a NEW array. Pure.
 */
export function mergeWsEndpoint(list, handshake) {
  const arr = Array.isArray(list) ? list.slice() : [];
  const url = handshake && typeof handshake.url === 'string' ? handshake.url : '';
  if (!url) return arr;
  const rec = {
    url,
    host: handshake.host || '',
    origin: handshake.origin || '',
    hasCookie: !!handshake.hasCookie,
    sameOrigin: handshake.sameOrigin !== false,
    cswsh: isCswshCandidate(handshake),
  };
  const idx = arr.findIndex((e) => e.url === url);
  if (idx === -1) arr.push(rec);
  else arr[idx] = { ...arr[idx], ...rec };
  return arr;
}

/**
 * Produce a fuzzed frame: inject `payload` into the first string field of a JSON
 * frame (preserving structure), or return the bare payload for a non-JSON frame.
 * Pure — the caller decides whether to actually send it (a human-driven step).
 */
export function mutateFrame(frame, payload) {
  const p = typeof payload === 'string' ? payload : String(payload);
  if (typeof frame !== 'string' || !frame) return p;
  let obj;
  try {
    obj = JSON.parse(frame);
  } catch (_) {
    return p;
  }
  if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
    for (const k of Object.keys(obj)) {
      if (typeof obj[k] === 'string') {
        obj[k] = p;
        return JSON.stringify(obj);
      }
    }
  }
  return p;
}

/**
 * Shape discovered WebSocket surface into normalized Findings:
 *   - ws-endpoint (informational)   the observed socket(s)
 *   - ws-cswsh (low)                cookie-authed socket — verify Origin checks
 *   - ws-injection (medium)         a fuzzed frame result (human-driven)
 * Emits nothing without endpoints. Pure.
 */
export function buildWsFindings(
  { host = '', endpoints = [], injections = [] } = {},
  now = new Date().toISOString()
) {
  const eps = Array.isArray(endpoints) ? endpoints : [];
  const out = [];
  if (!eps.length) return out;

  const lines = eps
    .slice(0, 50)
    .map((e) => `${e.url}${e.cswsh ? ' [cswsh?]' : ''}`)
    .join('\n');
  out.push(
    normalizeFinding(
      {
        host,
        type: 'ws-endpoint',
        severity: 'informational',
        title: `${eps.length} WebSocket endpoint${eps.length === 1 ? '' : 's'} observed`,
        evidence: lines,
        source: 'ws-recon',
      },
      now
    )
  );

  for (const e of eps) {
    if (!e || !e.cswsh) continue;
    out.push(
      normalizeFinding(
        {
          host,
          type: 'ws-cswsh',
          severity: 'low',
          title: 'Cross-Site WebSocket Hijacking candidate',
          evidence: `${e.url} authenticates via ambient cookies with no per-connection token. Verify the server validates the Origin header (open it from a foreign origin) — candidate, not confirmed.`,
          source: 'ws-recon',
          ref: e.url,
        },
        now
      )
    );
  }

  for (const inj of Array.isArray(injections) ? injections : []) {
    out.push(
      normalizeFinding(
        {
          host,
          type: 'ws-injection',
          severity: 'medium',
          title: `WebSocket frame injection candidate (${inj.family || 'payload'})`,
          evidence: `Fuzzed frame to ${inj.url} elicited an anomalous response. Verify manually.`,
          source: 'ws-recon',
          ref: inj.url,
        },
        now
      )
    );
  }

  return out;
}
