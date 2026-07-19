// Confidence-scored validation gate — pure, unit-testable (no chrome.*/network).
//
// Sits between the findings store and the report/escalation consumers. Given a
// finding plus the evidence already on it, it computes a DETERMINISTIC 0-100
// confidence, assigns a band, and lists WHY the score landed there and WHAT
// would raise it. Its job is to keep false positives out of reports — noisy
// submissions destroy platform reputation.
//
// Posture mirrors utils/escalation.js:
//   • It classifies and annotates; it never executes, fetches, or mutates input.
//   • It never deletes a finding — low confidence is tagged, not dropped.
//   • The caller's `confidence` is IGNORED and recomputed (never trust the input).
//   • `needMore` only ever names REAL escalation verbs (checked against
//     ACTION_VERBS), so it hands the human a step the engine can actually run.
//
// The score is deterministic rules only. An optional LLM may later turn
// `reasons[]` into prose, but that lives in a SEPARATE module — never here.

import { ACTION_VERBS } from './escalation';

// Band floors (inclusive). A finding's band is the highest floor it clears.
export const BANDS = { confirmed: 80, likely: 55, tentative: 30, noise: 0 };

// Report shows band >= likely; tentative/noise stay in the low-confidence view.
export const DEFAULT_REPORT_THRESHOLD = BANDS.likely;

// Ordered strongest -> weakest, for band comparisons.
const BAND_ORDER = ['confirmed', 'likely', 'tentative', 'noise'];

// All weights/caps live here so they're tunable and asserted directly by tests.
export const RULES = {
  domXssBase: 30,
  // A runtime canary that reached the sink (domProbe) is strong reachability
  // evidence — additive, still human-verified for actual exploitability.
  probeConfirmedBonus: 25,
  reflection: {
    js: 50,
    'html-body': 45,
    attribute: 15,
    string: -5,
    url: -5,
    rfl: 0,
    none: -35,
  },
  taintedSinkBonus: 25,

  injectionBase: 30,
  // Applied by finding type: 'sqli-boolean' (strong) vs 'sqli-time' (noisier).
  oracle: { boolean: 50, time: 35 },

  secretBase: {
    aws_access_key: 78,
    stripe_key: 78,
    github_token: 75,
    google_api_key: 72,
    slack_token: 72,
    private_key: 85,
    jwt: 50,
  },
  secretCap: 90, // never fully certain — we never USE the key to confirm it's live
  entropyHigh: 4.0,
  entropyHighBonus: 8,
  entropyLow: 3.0,
  entropyLowPenalty: -15,

  headersBase: 35,
  headersCap: 45, // a missing header is a signal, not a demonstrated vuln

  oobBase: 40,
  oobHitBonus: 55,

  // A nuclei template match is a curated known-vuln signature — high-signal, but
  // still human-verified (nuclei has some false positives).
  nucleiBase: 75,

  unknownBase: 35,
};

const SECRET_TYPES = new Set(Object.keys(RULES.secretBase));

function clamp(n, lo = 0, hi = 100) {
  return Math.max(lo, Math.min(hi, n));
}

/** Band for a numeric confidence, using the BANDS floors. */
export function bandFor(confidence) {
  if (confidence >= BANDS.confirmed) return 'confirmed';
  if (confidence >= BANDS.likely) return 'likely';
  if (confidence >= BANDS.tentative) return 'tentative';
  return 'noise';
}

function hasTaintedSink(f) {
  return !!(f && f.sink && Array.isArray(f.sources) && f.sources.length > 0);
}

// Only ever suggest verbs the engine actually has. Silently drops anything else,
// so a typo here can never hand the human a non-runnable step.
function pushVerb(list, verb) {
  if (ACTION_VERBS[verb] && !list.includes(verb)) list.push(verb);
}

function scoreSecret(finding, reasons) {
  const type = finding.type;
  let score = RULES.secretBase[type];
  reasons.push(`secret type "${type}" matched by pattern`);
  if (typeof finding.entropy === 'number') {
    if (finding.entropy >= RULES.entropyHigh) {
      score += RULES.entropyHighBonus;
      reasons.push('high Shannon entropy (looks like a live credential)');
    } else if (finding.entropy < RULES.entropyLow) {
      score += RULES.entropyLowPenalty;
      reasons.push('low entropy (likely a placeholder/example value)');
    }
  }
  score = Math.min(score, RULES.secretCap);
  reasons.push('not verified live — we never use the key to confirm it');
  return score;
}

function scoreDomXss(finding, reasons, needMore) {
  let score = RULES.domXssBase;
  const ctx = finding.reflection;
  const tainted = hasTaintedSink(finding);
  if (ctx && Object.prototype.hasOwnProperty.call(RULES.reflection, ctx)) {
    score += RULES.reflection[ctx];
    reasons.push(`reflection context: ${ctx}`);
    if (ctx !== 'js' && ctx !== 'html-body')
      pushVerb(needMore, 'confirm_reflection');
  } else if (!tainted) {
    // No reflection evidence AND no tainted sink — reachability is unconfirmed.
    reasons.push('no reflection context or tainted sink observed yet');
    pushVerb(needMore, 'confirm_reflection');
  }
  if (tainted) {
    // A DOM source flowing to a dangerous sink is the core DOM-XSS evidence.
    score += RULES.taintedSinkBonus;
    reasons.push(`tainted source flows to sink "${finding.sink}"`);
  }
  if (finding.probeConfirmed) {
    score += RULES.probeConfirmedBonus;
    reasons.push('runtime canary reached the sink (confirmed reachability)');
  }
  return score;
}

// Real pipeline encodes the oracle signal in the type ('sqli-boolean'/'sqli-time').
function scoreInjection(type, reasons, needMore) {
  let score = RULES.injectionBase;
  if (type === 'sqli-time') {
    score += RULES.oracle.time;
    reasons.push('time-based blind SQLi signal observed');
    reasons.push('timing can be noisy — corroborate');
    pushVerb(needMore, 'differential_probe');
  } else {
    score += RULES.oracle.boolean;
    reasons.push('boolean-based differential responded to the payload');
  }
  return score;
}

/**
 * Score ONE finding from the evidence already on it. Pure and deterministic.
 * @returns {{confidence:number, band:string, reasons:string[], needMore:string[]}}
 */
export function scoreFinding(finding = {}) {
  const type = finding && typeof finding.type === 'string' ? finding.type : '';
  const reasons = [];
  const needMore = [];
  let score;

  if (SECRET_TYPES.has(type)) {
    score = scoreSecret(finding, reasons);
    pushVerb(needMore, 'manual');
  } else if (type === 'dom-xss') {
    score = scoreDomXss(finding, reasons, needMore);
  } else if (type === 'sqli-boolean' || type === 'sqli-time') {
    score = scoreInjection(type, reasons, needMore);
  } else if (type === 'oob') {
    score = RULES.oobBase;
    if (finding.oobHit) {
      score += RULES.oobHitBonus;
      reasons.push('out-of-band callback received');
    } else {
      reasons.push('no out-of-band callback yet');
      pushVerb(needMore, 'manual');
    }
  } else if (type === 'header') {
    score = Math.min(RULES.headersBase, RULES.headersCap);
    reasons.push('missing/weak header is a signal, not a demonstrated vuln');
  } else if (type === 'nuclei') {
    score = RULES.nucleiBase;
    reasons.push('nuclei template matched (curated known-vuln signature)');
  } else {
    score = RULES.unknownBase;
    reasons.push(
      `unknown finding type "${type || '(none)'}" — defaulting to tentative`
    );
    pushVerb(needMore, 'manual');
  }

  const confidence = clamp(Math.round(score));
  return { confidence, band: bandFor(confidence), reasons, needMore };
}

/**
 * Return a NEW finding with `.validation` attached and the top-level
 * `.confidence` normalized to the recomputed 0-100 score. Input is untouched.
 */
export function validateFinding(finding = {}) {
  const validation = scoreFinding(finding);
  return { ...finding, confidence: validation.confidence, validation };
}

/** Validate a list. Non-arrays yield an empty array. */
export function validateFindings(list) {
  return (Array.isArray(list) ? list : []).map((f) => validateFinding(f));
}

/** Keep findings whose confidence clears the threshold. Scores on the fly. */
export function filterForReport(
  list,
  { minConfidence = DEFAULT_REPORT_THRESHOLD } = {}
) {
  return (Array.isArray(list) ? list : []).filter(
    (f) => scoreFinding(f).confidence >= minConfidence
  );
}

/** True when a finding's band is at least `minBand` (default 'likely'). */
export function canEscalateFinding(finding, { minBand = 'likely' } = {}) {
  const band = scoreFinding(finding).band;
  const gate = BAND_ORDER.indexOf(minBand);
  const got = BAND_ORDER.indexOf(band);
  if (gate === -1 || got === -1) return false;
  return got <= gate; // stronger or equal band
}
