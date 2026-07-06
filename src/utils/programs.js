// Program & payout tracker — pure, unit-testable model (no chrome.*/network).
//
// Tracks the bug-bounty programs you hunt and the submissions/payouts against
// them, so you can see pipeline value and earnings at a glance. This is the
// "part-time income" bookkeeping from the §0 vision — honest accounting, not a
// promise of passive money.

export const PLATFORMS = ['HackerOne', 'Bugcrowd', 'Intigriti', 'Immunefi', 'YesWeHack', 'Private', 'Other'];

// Submission lifecycle. `paid` implies a bounty; `resolved` may or may not pay.
export const SUBMISSION_STATES = ['draft', 'submitted', 'triaged', 'resolved', 'paid', 'duplicate', 'n/a'];

// States that still might earn money (i.e. counted as "pipeline").
const OPEN_STATES = new Set(['draft', 'submitted', 'triaged', 'resolved']);

let _seq = 0;
function id(prefix) {
  _seq += 1;
  return `${prefix}_${Date.now().toString(36)}_${_seq}`;
}

/** Create a program record. */
export function createProgram({ name, platform = 'Other', url = '', scopeRef = '', notes = '' } = {}) {
  return {
    id: id('prog'),
    name: (name || 'Untitled program').trim(),
    platform: PLATFORMS.includes(platform) ? platform : 'Other',
    url: url.trim(),
    scopeRef: scopeRef.trim(), // links to a scope host pattern
    notes: notes.trim(),
    createdAt: new Date().toISOString(),
  };
}

/** Create a submission record tied to a program. */
export function createSubmission({ programId, title, severity = 'medium', state = 'draft', bounty = 0, currency = 'USD', submittedAt = '', notes = '' } = {}) {
  const amount = Number(bounty);
  return {
    id: id('sub'),
    programId: programId || '',
    title: (title || 'Untitled finding').trim(),
    severity,
    state: SUBMISSION_STATES.includes(state) ? state : 'draft',
    bounty: Number.isFinite(amount) && amount > 0 ? amount : 0,
    currency: currency || 'USD',
    submittedAt: submittedAt || new Date().toISOString(),
    notes: (notes || '').trim(),
  };
}

/**
 * Aggregate stats across submissions.
 * @param {Array} submissions
 * @returns {{ earned:number, pipeline:number, counts:object, paidCount:number, openCount:number, total:number }}
 *   `earned`   = sum of bounties on `paid` submissions
 *   `pipeline` = count of still-open submissions (may still pay)
 */
export function summarizeSubmissions(submissions = []) {
  const counts = Object.fromEntries(SUBMISSION_STATES.map((s) => [s, 0]));
  let earned = 0;
  let paidCount = 0;
  let openCount = 0;
  for (const sub of Array.isArray(submissions) ? submissions : []) {
    const state = SUBMISSION_STATES.includes(sub.state) ? sub.state : 'draft';
    counts[state] += 1;
    if (state === 'paid') {
      earned += Number(sub.bounty) || 0;
      paidCount += 1;
    }
    if (OPEN_STATES.has(state)) openCount += 1;
  }
  return {
    earned,
    pipeline: openCount,
    counts,
    paidCount,
    openCount,
    total: (Array.isArray(submissions) ? submissions.length : 0),
  };
}

/** Per-program rollup: attach a submission summary + earned total to each program. */
export function summarizeByProgram(programs = [], submissions = []) {
  const byProg = new Map();
  for (const s of Array.isArray(submissions) ? submissions : []) {
    if (!byProg.has(s.programId)) byProg.set(s.programId, []);
    byProg.get(s.programId).push(s);
  }
  return (Array.isArray(programs) ? programs : []).map((p) => {
    const subs = byProg.get(p.id) || [];
    return { ...p, submissionCount: subs.length, summary: summarizeSubmissions(subs) };
  });
}
