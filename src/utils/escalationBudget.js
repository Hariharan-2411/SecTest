// Confidence-aware autonomy (H1) — pure, unit-testable (no chrome.*/network).
//
// Scales an escalation's depth + budget by the SEED finding's validation band, so
// the loop spends where the evidence is strongest: cheap, shallow probes for a
// tentative finding; a deeper, richer plan for a confirmed one. Composes with the
// autonomy dial (C) — the dial governs auto-run vs gate; this governs how far.
//
// Lives in its own module to avoid a cycle: validate.js imports escalation.js's
// ACTION_VERBS, so escalation.js can't import validate.js — but this module can
// import both. Nothing imports it back.

import { scoreFinding } from './validate';
import { MAX_DEPTH, DEFAULT_ESCALATION_BUDGET } from './escalation';

// Band → { maxDepth, budget }, relative to the escalation defaults.
export const BAND_PLAN = {
  confirmed: { maxDepth: MAX_DEPTH + 1, budget: Math.round(DEFAULT_ESCALATION_BUDGET * 1.2) },
  likely: { maxDepth: MAX_DEPTH, budget: DEFAULT_ESCALATION_BUDGET },
  tentative: { maxDepth: Math.max(1, MAX_DEPTH - 1), budget: Math.round(DEFAULT_ESCALATION_BUDGET * 0.4) },
  noise: { maxDepth: 0, budget: 0 },
};

/**
 * The escalation depth + budget a finding earns from its validation band. Pure;
 * never throws; defaults to the `likely` plan for unknown/garbage input.
 * @returns {{maxDepth:number, budget:number}}
 */
export function escalationBudgetFor(finding) {
  const { band } = scoreFinding(finding && typeof finding === 'object' ? finding : {});
  return BAND_PLAN[band] || BAND_PLAN.likely;
}
