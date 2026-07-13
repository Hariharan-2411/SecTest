// Finding enrichment — attach CWE + CVSS 3.1 baseline metadata to a finding.
// Pure, deterministic, offline (no chrome.*/network).
//
// ADDITIVE ONLY: it never mutates the finding's `severity` (source-set) or the
// gate's `confidence`. It adds reference metadata reports expect. EPSS/KEV are
// CVE-keyed and only carried through when the finding already has a `cve`.
//
// The CVSS base score is computed from the official CVSS 3.1 formula, so each
// class only declares a vector and the score is correct (and testable).

// --- CVSS 3.1 base-score formula -------------------------------------------

const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC = { L: 0.77, H: 0.44 };
const UI = { N: 0.85, R: 0.62 };
const CIA = { H: 0.56, L: 0.22, N: 0 };
const PR_UNCHANGED = { N: 0.85, L: 0.62, H: 0.27 };
const PR_CHANGED = { N: 0.85, L: 0.68, H: 0.5 };

function parseVector(vector) {
  if (typeof vector !== 'string' || !/^CVSS:3\.[01]\//.test(vector))
    return null;
  const m = {};
  for (const part of vector.split('/').slice(1)) {
    const [k, v] = part.split(':');
    if (k && v) m[k] = v;
  }
  for (const k of ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']) {
    if (!(k in m)) return null;
  }
  return m;
}

// CVSS 3.1 roundup: round up to one decimal place (spec's integer trick).
function roundup(input) {
  const i = Math.round(input * 100000);
  if (i % 10000 === 0) return i / 100000;
  return (Math.floor(i / 10000) + 1) / 10;
}

/** Official CVSS 3.1 base score for a vector string, or 0 if invalid. */
export function cvssBaseScore(vector) {
  const m = parseVector(vector);
  if (!m) return 0;
  const changed = m.S === 'C';
  const av = AV[m.AV];
  const ac = AC[m.AC];
  const ui = UI[m.UI];
  const pr = (changed ? PR_CHANGED : PR_UNCHANGED)[m.PR];
  const c = CIA[m.C];
  const i = CIA[m.I];
  const a = CIA[m.A];
  if ([av, ac, ui, pr, c, i, a].some((x) => x == null)) return 0;

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = changed
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss * 0.9731 - 0.02, 13)
    : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av * ac * pr * ui;
  const base = changed
    ? 1.08 * (impact + exploitability)
    : impact + exploitability;
  return roundup(Math.min(base, 10));
}

/** Qualitative CVSS 3.1 severity band for a base score. */
export function cvssSeverity(score) {
  if (score <= 0) return 'none';
  if (score < 4.0) return 'low';
  if (score < 7.0) return 'medium';
  if (score < 9.0) return 'high';
  return 'critical';
}

// --- Class → CWE/CVSS table -------------------------------------------------

const SECRET_META = {
  cwe: 'CWE-798',
  cweName: 'Use of Hard-coded Credentials',
  vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
};

export const CLASS_META = {
  'dom-xss': {
    cwe: 'CWE-79',
    cweName: 'Cross-site Scripting (XSS)',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
  },
  'sqli-boolean': {
    cwe: 'CWE-89',
    cweName: 'SQL Injection',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
  },
  'sqli-time': {
    cwe: 'CWE-89',
    cweName: 'SQL Injection (blind, time-based)',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
  },
  header: {
    cwe: 'CWE-693',
    cweName: 'Protection Mechanism Failure',
    vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N',
  },
  oob: {
    cwe: 'CWE-918',
    cweName: 'Server-Side Request Forgery (SSRF)',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',
  },
  aws_access_key: SECRET_META,
  stripe_key: SECRET_META,
  github_token: SECRET_META,
  google_api_key: SECRET_META,
  slack_token: SECRET_META,
  private_key: SECRET_META,
  jwt: {
    cwe: 'CWE-522',
    cweName: 'Insufficiently Protected Credentials',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
  },
};

/**
 * Attach CWE + CVSS baseline (and normalized cve/epss/kev) to a finding.
 * Returns a NEW object; never mutates input; never touches severity/confidence.
 */
export function enrichFinding(finding = {}) {
  const meta = CLASS_META[finding.type];
  const cvss = meta
    ? (() => {
        const baseScore = cvssBaseScore(meta.vector);
        return {
          vector: meta.vector,
          baseScore,
          severity: cvssSeverity(baseScore),
        };
      })()
    : null;

  // EPSS/KEV are CVE-keyed — only meaningful when the finding carries a CVE.
  const cve =
    typeof finding.cve === 'string' && finding.cve ? finding.cve : null;
  const epss = cve && typeof finding.epss === 'number' ? finding.epss : null;
  const kev = cve ? finding.kev === true : false;

  return {
    ...finding,
    cwe: meta ? meta.cwe : null,
    cweName: meta ? meta.cweName : null,
    cvss,
    cve,
    epss,
    kev,
  };
}

/** Enrich a list. Non-arrays yield an empty array. */
export function enrichFindings(list) {
  return (Array.isArray(list) ? list : []).map((f) => enrichFinding(f));
}
