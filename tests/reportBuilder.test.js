import { describe, it, expect } from '@jest/globals';
import { buildReport, REPORT_PLATFORMS, SEVERITIES } from '../src/utils/reportBuilder';

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
