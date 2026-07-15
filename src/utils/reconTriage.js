// Recon triage finalization — Phase 5.4. Pure. Runs the agent's collected
// findings through the finding-intelligence layer we already built:
//   dedupe → validate (confidence gate) → enrich (CWE/CVSS) → rank,
// and splits out the report-worthy subset. This is the seam that plugs the
// recon agent's output into the same pipeline the extension's own findings use.

import { dedupeFindings, summarizeFindings } from './findings';
import { validateFindings, filterForReport } from './validate';
import { enrichFindings } from './enrich';
import { rankTriage } from './reconAgent';

/**
 * Turn raw agent findings into a ranked triage draft.
 * @param {object[]} findings
 * @param {{crossHost?:boolean, minConfidence?:number}} opts
 * @returns {{ranked:object[], reportworthy:object[], summary:object}}
 */
export function finalizeTriage(
  findings,
  { crossHost = false, minConfidence } = {}
) {
  const deduped = dedupeFindings(Array.isArray(findings) ? findings : [], {
    crossHost,
  });
  const processed = enrichFindings(validateFindings(deduped)); // additive: confidence + CWE/CVSS
  const ranked = rankTriage(processed); // severity → confidence, with a rank
  const reportworthy =
    minConfidence != null
      ? ranked.filter((f) => (f.confidence || 0) >= minConfidence)
      : filterForReport(ranked);
  return { ranked, reportworthy, summary: summarizeFindings(ranked) };
}
