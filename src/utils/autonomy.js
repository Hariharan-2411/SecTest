// Autonomy dial (C1) — pure, unit-testable (no chrome.*/network).
//
// Governs how much of a loop (escalation, recon, signal suggestions) runs without
// a human tap. The dial changes only whether SAFE steps auto-run and whether a
// loop auto-initiates — ACTIVE steps ALWAYS gate for a human, at every level.
// That last rule is the non-negotiable guardrail; the dial can never weaken it.

export const AUTONOMY_LEVELS = ['manual', 'assisted', 'auto-safe'];
export const DEFAULT_AUTONOMY = 'assisted';

function normLevel(level) {
  return AUTONOMY_LEVELS.includes(level) ? level : DEFAULT_AUTONOMY;
}

/**
 * Decide what to do with a step of a given risk at a given autonomy level.
 * @param {string} level  one of AUTONOMY_LEVELS (unknown → DEFAULT_AUTONOMY)
 * @param {string} risk   'safe' | 'active' | anything else
 * @returns {'run'|'gate'|'skip'}
 *   - active → always 'gate' (core guardrail, independent of level)
 *   - safe   → 'run' except under 'manual', which gates everything
 *   - other  → 'skip' (nothing executable to auto-run)
 */
export function decideAutonomy(level, risk) {
  if (risk === 'active') return 'gate';
  if (risk === 'safe') return normLevel(level) === 'manual' ? 'gate' : 'run';
  return 'skip';
}

/** Whether this level auto-initiates the safe part of a suggestion (auto-safe only). */
export function autoTriggerEnabled(level) {
  return level === 'auto-safe';
}
