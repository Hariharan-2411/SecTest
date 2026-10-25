// Continuous-monitoring auto-triage digest (G1) — pure, unit-testable.
//
// Turns a recon DELTA (new hosts / endpoints / findings since the last run) into a
// ranked "what changed and what to look at first" digest, reusing the same signal
// ranker as the Findings suggestions (signals.detectEscalationSignals). The
// wiring (G2) has the cron / companion watch feed the delta in and post the
// formatted digest via notify. Pure; never throws.

import { detectEscalationSignals } from './signals';

/**
 * @param {{newHosts?:string[], newEndpoints?:string[], newFindings?:object[]}} delta
 * @param {{scope?:object, allFindings?:object[], max?:number}} opts
 *   allFindings — analyze the new findings for chains against the FULL set, but
 *   surface only the new ones.
 */
export function buildReconDigest(delta, opts) {
  const { scope, allFindings, max = 5 } = opts && typeof opts === 'object' ? opts : {};
  const d = delta && typeof delta === 'object' ? delta : {};
  const newHosts = Array.isArray(d.newHosts) ? d.newHosts.filter((h) => typeof h === 'string') : [];
  const newEndpoints = Array.isArray(d.newEndpoints) ? d.newEndpoints.filter((e) => typeof e === 'string') : [];
  const newFindings = Array.isArray(d.newFindings) ? d.newFindings.filter(Boolean) : [];

  const useAll = Array.isArray(allFindings) && allFindings.length > 0;
  const pool = useAll ? allFindings : newFindings;
  const newIds = new Set(newFindings.map((f) => f && f.id).filter((id) => id != null).map(String));
  const ranked = detectEscalationSignals(pool, { scope, max: Math.max(max * 2, 10) });
  const topMoves = (useAll ? ranked.filter((s) => newIds.has(String(s.findingId))) : ranked).slice(0, max);

  const counts = { hosts: newHosts.length, endpoints: newEndpoints.length, findings: newFindings.length };
  const empty = !counts.hosts && !counts.endpoints && !counts.findings;
  const summary = empty
    ? 'No new attack surface since the last run.'
    : `${counts.hosts} new host(s), ${counts.endpoints} new endpoint(s), ${counts.findings} new finding(s)` +
      (topMoves.length ? ` — ${topMoves.length} worth a look first.` : '.');

  return {
    empty,
    counts,
    newHosts: newHosts.slice(0, max),
    newEndpoints: newEndpoints.slice(0, max),
    topMoves,
    summary,
  };
}

/** Render a digest as plain text suitable for a notify webhook. Pure; never throws. */
export function formatReconDigest(digest) {
  const d = digest && typeof digest === 'object' ? digest : {};
  if (d.empty || !d.summary) return 'Recon: no new attack surface since the last run.';
  const lines = [`🔭 Recon digest — ${d.summary}`];
  if (Array.isArray(d.newHosts) && d.newHosts.length) lines.push('New hosts: ' + d.newHosts.join(', '));
  if (Array.isArray(d.newEndpoints) && d.newEndpoints.length) lines.push('New endpoints: ' + d.newEndpoints.join(', '));
  if (Array.isArray(d.topMoves) && d.topMoves.length) {
    lines.push('Look at first:');
    for (const m of d.topMoves) lines.push(`• ${m.title || m.type} — ${m.reason}`);
  }
  return lines.join('\n');
}
