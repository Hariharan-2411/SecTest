// JS-file change detection — pure, unit-testable (no chrome.*/network).
//
// The background worker fetches in-scope JS files; these helpers turn each file
// into a compact "snapshot" (hash + extracted endpoints + likely secrets) and
// diff two snapshots so monitoring can alert on *new* attack surface. New
// endpoints appearing in a JS bundle are one of the highest-signal bug-bounty
// leads (§7 of the plan), so diffing beats a one-off scan.
//
// Purely analytical: it inspects text you already fetched from an in-scope
// target. It never fetches or sends anything itself.

import { findInlineEndpoints } from './extraction';
// Secret detection lives in secrets.js (single source of truth, shared with the
// passive page recon and deep-JS scan). Re-exported so existing importers of
// findSecrets from this module keep working.
import { findSecrets } from './secrets';

export { findSecrets };

/** Fast, stable, non-crypto content hash (djb2 xor variant) as a hex string. */
export function hashText(text) {
  const s = typeof text === 'string' ? text : String(text || '');
  let h = 5381;
  for (let i = 0; i < s.length; i++) {
    h = ((h << 5) + h) ^ s.charCodeAt(i);
    h |= 0; // keep 32-bit
  }
  // include length to further reduce collisions
  return (h >>> 0).toString(16) + '-' + s.length.toString(16);
}

/**
 * Build a snapshot of one JS file.
 * @param {string} url   the script URL (identity key)
 * @param {string} text  the fetched file body
 * @param {string} [now] ISO timestamp (injectable for tests)
 */
export function makeSnapshot(url, text, now = new Date().toISOString()) {
  const body = typeof text === 'string' ? text : '';
  return {
    url,
    hash: hashText(body),
    size: body.length,
    endpoints: findInlineEndpoints(body).sort(),
    secrets: findSecrets(body),
    capturedAt: now,
  };
}

function arrDiff(prev = [], next = []) {
  const p = new Set(prev);
  const n = new Set(next);
  return {
    added: next.filter((x) => !p.has(x)),
    removed: prev.filter((x) => !n.has(x)),
  };
}

/**
 * Diff two snapshots of the same file. `prev` may be null (first sighting).
 * @returns {{url, isNew, changed, addedEndpoints, removedEndpoints, newSecrets}}
 */
export function diffSnapshots(prev, next) {
  if (!next) return { url: '', isNew: false, changed: false, addedEndpoints: [], removedEndpoints: [], newSecrets: [] };
  if (!prev) {
    return {
      url: next.url,
      isNew: true,
      changed: true,
      addedEndpoints: next.endpoints.slice(),
      removedEndpoints: [],
      newSecrets: next.secrets.slice(),
    };
  }
  const eps = arrDiff(prev.endpoints, next.endpoints);
  const prevSecretKeys = new Set((prev.secrets || []).map((s) => s.type + ':' + s.preview));
  const newSecrets = (next.secrets || []).filter((s) => !prevSecretKeys.has(s.type + ':' + s.preview));
  return {
    url: next.url,
    isNew: false,
    changed: prev.hash !== next.hash,
    addedEndpoints: eps.added,
    removedEndpoints: eps.removed,
    newSecrets,
  };
}

/** True when a diff is worth alerting a human about. */
export function isInterestingDiff(diff) {
  if (!diff) return false;
  return Boolean(diff.isNew || diff.addedEndpoints.length || diff.newSecrets.length);
}

/** One-line human summary of a diff (for notifications / UI). */
export function summarizeDiff(diff) {
  if (!diff) return '';
  const parts = [];
  if (diff.isNew) parts.push('new file');
  if (diff.addedEndpoints.length) parts.push(`+${diff.addedEndpoints.length} endpoint(s)`);
  if (diff.removedEndpoints.length) parts.push(`-${diff.removedEndpoints.length} endpoint(s)`);
  if (diff.newSecrets.length) parts.push(`⚠️ ${diff.newSecrets.length} secret(s)`);
  return parts.join(', ') || 'no change';
}
