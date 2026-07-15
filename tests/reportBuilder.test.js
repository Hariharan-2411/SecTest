import { describe, it, expect } from '@jest/globals';
import {
  buildReport,
  buildReports,
  REPORT_PLATFORMS,
  SEVERITIES,
} from '../src/utils/reportBuilder';

const finding = {
  title: 'Reflected XSS',
  target: 'app.example.com',
  program: 'Example',
  ref: 'WSTG-INPV-01',
  severity: 'high',
  summary: 'User input is reflected without encoding.',
  steps: ['Visit /search?q=<x>', 'Observe payload executes'],
  impact: 'Session theft.',
  evidence: 'GET /search?q=<script> HTTP/1.1',
};

describe('buildReport', () => {
  it('produces a HackerOne draft with the expected sections', () => {
    const md = buildReport(finding, 'hackerone');
    expect(md).toContain('# Reflected XSS on app.example.com');
    expect(md).toContain('**Severity:** High');
    expect(md).toContain('## Steps To Reproduce');
    expect(md).toContain('1. Visit /search?q=<x>');
    expect(md).toContain('## Evidence');
    expect(md).toContain('WSTG-INPV-01');
  });

  it('uses Bugcrowd section headings for that platform', () => {
    const md = buildReport(finding, 'bugcrowd');
    expect(md).toContain('## Vulnerability Details');
    expect(md).toContain('## Steps to Reproduce');
  });

  it('defaults missing fields safely', () => {
    const md = buildReport({ title: 'X' });
    expect(md).toContain('# X');
    expect(md).toContain('**Severity:** Medium');
    expect(md).toContain('_Add reproduction steps._');
  });

  it('every platform id builds a non-empty report', () => {
    for (const p of REPORT_PLATFORMS) {
      expect(buildReport(finding, p.id).length).toBeGreaterThan(20);
    }
  });

  it('exposes the standard severities', () => {
    expect(SEVERITIES).toContain('critical');
    expect(SEVERITIES).toContain('informational');
  });
});

describe('buildReport — confidence surfacing', () => {
  it('renders a Confidence meta line when a confidence is supplied', () => {
    const md = buildReport({ title: 'X', confidence: 82, band: 'likely' });
    expect(md).toContain('**Confidence:** 82% (likely)');
  });

  it('derives the band from the confidence when band is omitted', () => {
    const md = buildReport({ title: 'X', confidence: 70 });
    expect(md).toContain('**Confidence:** 70% (likely)');
  });

  it('shows a low-confidence warning banner for a tentative finding', () => {
    const md = buildReport({ title: 'X', confidence: 34, band: 'tentative' });
    expect(md).toMatch(/low confidence/i);
    expect(md).toContain('34%');
  });

  it('shows no warning banner for a confirmed finding', () => {
    const md = buildReport({ title: 'X', confidence: 90, band: 'confirmed' });
    expect(md).not.toMatch(/low confidence/i);
  });

  it('is backward compatible: no confidence means no Confidence line and no banner', () => {
    const md = buildReport({ title: 'X' });
    expect(md).not.toContain('**Confidence:**');
    expect(md).not.toMatch(/low confidence/i);
  });
});

describe('buildReports — gate filter over a findings list', () => {
  const raw = [
    {
      type: 'sqli-boolean',
      title: 'SQLi',
      host: 'app.example.com',
      severity: 'high',
      evidence: 'x',
    }, // 80 confirmed
    {
      type: 'dom-xss',
      reflection: 'attribute',
      title: 'Maybe XSS',
      host: 'app.example.com',
    }, // 45 tentative
  ];

  it('keeps only findings that clear the report threshold and builds their markdown', () => {
    const out = buildReports(raw, 'hackerone');
    expect(out).toHaveLength(1);
    expect(out[0].finding).toBe(raw[0]);
    expect(out[0].markdown).toContain('# SQLi on app.example.com');
    expect(out[0].markdown).toContain('**Confidence:** 80% (confirmed)');
  });

  it('honors a custom minConfidence', () => {
    const tentativeOnly = [raw[1]];
    expect(buildReports(tentativeOnly, 'hackerone')).toHaveLength(0); // 45 < default 55
    expect(
      buildReports(tentativeOnly, 'hackerone', { minConfidence: 40 })
    ).toHaveLength(1);
  });

  it('tolerates a non-array input', () => {
    expect(buildReports(null)).toEqual([]);
  });

  it('carries CWE/CVSS enrichment into batch report drafts', () => {
    const out = buildReports(
      [
        {
          type: 'sqli-boolean',
          title: 'SQLi',
          host: 'app.example.com',
          severity: 'high',
          evidence: 'x',
        },
      ],
      'hackerone'
    );
    expect(out).toHaveLength(1);
    expect(out[0].markdown).toContain('**CWE:** CWE-89');
    expect(out[0].markdown).toMatch(/\*\*CVSS:\*\* 9\.8/);
  });
});

describe('buildReport — CWE/CVSS enrichment', () => {
  it('renders CWE and CVSS meta lines when present', () => {
    const md = buildReport({
      title: 'X',
      cwe: 'CWE-89',
      cvss: {
        vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        baseScore: 9.8,
        severity: 'critical',
      },
    });
    expect(md).toContain('**CWE:** CWE-89');
    expect(md).toMatch(/\*\*CVSS:\*\* 9\.8 \(Critical\)/);
    expect(md).toContain('CVSS:3.1/AV:N');
  });

  it('omits CWE/CVSS lines when absent (backward compatible)', () => {
    const md = buildReport({ title: 'X' });
    expect(md).not.toContain('**CWE:**');
    expect(md).not.toContain('**CVSS:**');
  });
});
