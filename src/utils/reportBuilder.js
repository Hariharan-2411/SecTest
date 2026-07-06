// Report builder — pure, unit-testable markdown generation (no chrome.*/network).
//
// Turns a checklist finding + captured evidence into a submission-ready draft in
// a platform's expected shape. It ONLY formats what you give it — it never
// fabricates evidence, and the human always reviews and decides to submit.

export const REPORT_PLATFORMS = [
  { id: 'hackerone', label: 'HackerOne' },
  { id: 'bugcrowd', label: 'Bugcrowd' },
  { id: 'generic', label: 'Generic Markdown' },
];

// HackerOne-style severity buckets (CVSS-aligned words).
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'];

/** Normalize a finding into the fields the templates expect. */
function normalize(finding = {}) {
  const clean = (v) => (typeof v === 'string' ? v.trim() : v);
  const lines = (v) =>
    Array.isArray(v)
      ? v.filter(Boolean)
      : String(v || '')
          .split(/\r?\n/)
          .map((s) => s.trim())
          .filter(Boolean);
  return {
    title: clean(finding.title) || 'Untitled finding',
    target: clean(finding.target) || '',
    program: clean(finding.program) || '',
    ref: clean(finding.ref) || '', // WSTG / API / CWE id
    severity: SEVERITIES.includes(finding.severity) ? finding.severity : 'medium',
    summary: clean(finding.summary) || '',
    steps: lines(finding.steps),
    impact: clean(finding.impact) || '',
    remediation: clean(finding.remediation) || '',
    evidence: clean(finding.evidence) || '', // raw request/response paste
    references: lines(finding.references),
  };
}

function stepsBlock(steps) {
  if (!steps.length) return '_Add reproduction steps._';
  return steps.map((s, i) => `${i + 1}. ${s}`).join('\n');
}

function evidenceBlock(evidence) {
  if (!evidence) return '';
  return '\n## Evidence\n\n```http\n' + evidence + '\n```\n';
}

function referencesBlock(references, ref) {
  const items = [...references];
  if (ref) items.unshift(`Reference: ${ref}`);
  if (!items.length) return '';
  return '\n## References\n\n' + items.map((r) => `- ${r}`).join('\n') + '\n';
}

/**
 * Build a markdown report draft.
 * @param {object} finding  see `normalize` for fields
 * @param {string} platform one of REPORT_PLATFORMS ids
 * @returns {string} markdown
 */
export function buildReport(finding = {}, platform = 'hackerone') {
  const f = normalize(finding);
  const titleLine = f.target ? `# ${f.title} on ${f.target}` : `# ${f.title}`;
  const metaLine = [
    f.program && `**Program:** ${f.program}`,
    f.target && `**Target:** ${f.target}`,
    `**Severity:** ${f.severity[0].toUpperCase()}${f.severity.slice(1)}`,
    f.ref && `**Class:** ${f.ref}`,
  ]
    .filter(Boolean)
    .join('  \n');

  const summary = f.summary || '_Briefly describe the vulnerability._';
  const impact = f.impact || '_Describe the real-world impact for this target._';

  if (platform === 'bugcrowd') {
    return [
      titleLine,
      metaLine,
      '\n## Vulnerability Details',
      summary,
      '\n## Steps to Reproduce',
      stepsBlock(f.steps),
      evidenceBlock(f.evidence).trimEnd(),
      '\n## Impact',
      impact,
      f.remediation ? '\n## Recommended Fix\n\n' + f.remediation : '',
      referencesBlock(f.references, f.ref).trimEnd(),
      '\n---\n_Draft generated for review — verify scope & impact before submitting._',
    ]
      .filter((s) => s !== '')
      .join('\n');
  }

  if (platform === 'generic') {
    return [
      titleLine,
      metaLine,
      '\n## Summary',
      summary,
      '\n## Steps to Reproduce',
      stepsBlock(f.steps),
      evidenceBlock(f.evidence).trimEnd(),
      '\n## Impact',
      impact,
      f.remediation ? '\n## Remediation\n\n' + f.remediation : '',
      referencesBlock(f.references, f.ref).trimEnd(),
    ]
      .filter((s) => s !== '')
      .join('\n');
  }

  // Default: HackerOne
  return [
    titleLine,
    metaLine,
    '\n## Summary',
    summary,
    '\n## Steps To Reproduce',
    stepsBlock(f.steps),
    evidenceBlock(f.evidence).trimEnd(),
    '\n## Impact',
    impact,
    f.remediation ? '\n## Remediation\n\n' + f.remediation : '',
    referencesBlock(f.references, f.ref).trimEnd(),
    '\n---\n_Draft generated for review — confirm the finding and its impact before submitting. Never submit unverified or auto-generated reports._',
  ]
    .filter((s) => s !== '')
    .join('\n');
}
