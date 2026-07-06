// Diff two recon snapshots so scheduled monitoring can alert on NEW attack
// surface only (added subdomains/hosts/ports/findings), not on every run.
// Pure — no I/O. Mirrors the extension's jsdiff philosophy for agent output.

'use strict';

// Categories we track, each with a stable identity key for an item.
const KEYS = {
  subdomains: (x) => String(x),
  dns: (x) => String(x),
  http: (x) => (x && (x.url || x.input)) || String(x),
  ports: (x) => (x && (x.host != null || x.port != null) ? `${x.host || ''}:${x.port || ''}` : String(x)),
  findings: (x) => (x && (x.templateId || x.name) ? `${x.templateId || x.name}@${x.matched || ''}` : String(x)),
  urls: (x) => String(x),
};

const CATEGORIES = Object.keys(KEYS);

/** Normalize a raw snapshot to only known categories, each an array. */
function normalizeSnapshot(snap) {
  const out = {};
  for (const cat of CATEGORIES) out[cat] = Array.isArray(snap && snap[cat]) ? snap[cat] : [];
  return out;
}

function keyset(items, keyOf) {
  const m = new Map();
  for (const it of items) m.set(keyOf(it), it);
  return m;
}

/**
 * Diff previous → next.
 * @returns {{added:object, removed:object, counts:object, addedTotal:number, interesting:boolean}}
 *   added/removed are per-category arrays of the actual items.
 */
function diffSnapshots(prev, next) {
  const p = normalizeSnapshot(prev);
  const n = normalizeSnapshot(next);
  const added = {};
  const removed = {};
  const counts = {};
  let addedTotal = 0;

  for (const cat of CATEGORIES) {
    const keyOf = KEYS[cat];
    const pk = keyset(p[cat], keyOf);
    const nk = keyset(n[cat], keyOf);
    const a = [];
    const r = [];
    for (const [k, item] of nk) if (!pk.has(k)) a.push(item);
    for (const [k, item] of pk) if (!nk.has(k)) r.push(item);
    added[cat] = a;
    removed[cat] = r;
    counts[cat] = { added: a.length, removed: r.length };
    addedTotal += a.length;
  }

  // `first` run (no prev) counts everything as added but is flagged so callers
  // can choose whether to notify on the baseline.
  const isFirst = prev == null;
  return { added, removed, counts, addedTotal, interesting: addedTotal > 0, isFirst };
}

/** One-line human summary of a diff for notifications / history. */
function summarizeDiff(diff) {
  if (!diff) return '';
  const parts = [];
  for (const cat of CATEGORIES) {
    const c = diff.counts[cat];
    if (c && c.added) parts.push(`+${c.added} ${cat}`);
  }
  return parts.join(', ') || 'no new findings';
}

module.exports = { CATEGORIES, KEYS, normalizeSnapshot, diffSnapshots, summarizeDiff };
