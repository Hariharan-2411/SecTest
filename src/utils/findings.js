// Unified findings model — pure, unit-testable (no chrome.*/network).
//
// One normalized Finding shape that every source writes to: header analysis
// (Phase B), DOM-XSS taint candidates (Phase C), and the response oracles
// (Phase D). Centralizing them enables ranking, dedup (including across a
// program's subdomains), and a one-click hand-off to the report builder.
//
// A Finding is:
//   { id, host, type, severity, confidence, title, evidence, source, ref,
//     firstSeen, updatedAt }
//
// Analytical only: it merges and formats objects. It never fetches or claims —
// severity/confidence describe evidence strength; a human confirms before submit.

export const FINDING_SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'];

/**
 * Strongest constituent severity, bumped one level (capped 'critical'), because a
 * validated multi-step chain demonstrates more impact than any single part.
 */
export function deriveSeverity(constituents) {
  const idxs = (Array.isArray(constituents) ? constituents : [])
    .map((f) => FINDING_SEVERITIES.indexOf(f && f.severity))
    .filter((i) => i >= 0);
  if (!idxs.length) return 'informational';
  const base = Math.min(...idxs); // lower index = higher severity
  return FINDING_SEVERITIES[Math.max(0, base - 1)];
}

function severityRank(sev) {
  const i = FINDING_SEVERITIES.indexOf(sev);
  return i === -1 ? FINDING_SEVERITIES.length : i;
}

/** Coerce any source object into a complete, well-typed Finding. */
export function normalizeFinding(f = {}, now = new Date().toISOString()) {
  const norm = {
    id: f.id || `${f.type || 'finding'}:${f.title || ''}`,
    host: f.host || '',
    type: f.type || 'finding',
    severity: FINDING_SEVERITIES.includes(f.severity) ? f.severity : 'medium',
    confidence: typeof f.confidence === 'number' ? f.confidence : null,
    title: f.title || 'Finding',
    evidence: f.evidence || '',
    source: f.source || 'manual',
    ref: f.ref || '',
    firstSeen: f.firstSeen || now,
    updatedAt: now,
  };
  // Preserve optional display fields when present (DOM-XSS sink/sources).
  if (f.sink) norm.sink = f.sink;
  if (Array.isArray(f.sources)) norm.sources = f.sources;
  return norm;
}

/**
 * Upsert one finding into a single-host list, deduped by id. Preserves the
 * original firstSeen; refreshes the rest. Returns a NEW array.
 */
export function upsertFinding(list, f, now = new Date().toISOString()) {
  const arr = Array.isArray(list) ? list.slice() : [];
  const norm = normalizeFinding(f, now);
  const idx = arr.findIndex((x) => x.id === norm.id);
  if (idx === -1) {
    arr.push(norm);
  } else {
    arr[idx] = { ...norm, firstSeen: arr[idx].firstSeen || norm.firstSeen };
  }
  return arr;
}

/** Upsert many findings into a single-host list. */
export function upsertFindings(list, incoming, now = new Date().toISOString()) {
  let arr = Array.isArray(list) ? list.slice() : [];
  for (const f of Array.isArray(incoming) ? incoming : []) arr = upsertFinding(arr, f, now);
  return arr;
}

/** Dedup key. Cross-host collapses the same issue across subdomains of a program. */
export function dedupeKey(f, { crossHost = false } = {}) {
  const base = f.id || `${f.type}:${f.title}`;
  return crossHost ? String(base) : `${f.host || ''}|${base}`;
}

/**
 * Collapse a merged (possibly multi-host) list. On collision keeps the
 * higher-severity finding. Returns a NEW array.
 */
export function dedupeFindings(list, { crossHost = false } = {}) {
  const byKey = new Map();
  for (const f of Array.isArray(list) ? list : []) {
    const key = dedupeKey(f, { crossHost });
    const prev = byKey.get(key);
    if (!prev || severityRank(f.severity) < severityRank(prev.severity)) {
      byKey.set(key, f);
    }
  }
  return Array.from(byKey.values());
}

/** Sort by severity (critical→info), then confidence (desc). Returns a NEW array. */
export function sortFindings(list) {
  return [...(Array.isArray(list) ? list : [])].sort(
    (a, b) => severityRank(a.severity) - severityRank(b.severity) || (b.confidence || 0) - (a.confidence || 0)
  );
}

/** Severity counts for a summary strip. */
export function summarizeFindings(list) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0, total: 0 };
  for (const f of Array.isArray(list) ? list : []) {
    if (counts[f.severity] != null) counts[f.severity]++;
    counts.total++;
  }
  return counts;
}

/** Map a Finding into the shape reportBuilder.buildReport expects. */
export function toReportFinding(f = {}) {
  return {
    title: f.title || 'Finding',
    target: f.host || '',
    severity: FINDING_SEVERITIES.includes(f.severity) ? f.severity : 'medium',
    ref: f.ref || '',
    summary: f.evidence || '',
    evidence: f.evidence || '',
  };
}
