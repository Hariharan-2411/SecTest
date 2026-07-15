import { describe, it, expect } from '@jest/globals';
import { finalizeTriage } from '../src/utils/reconTriage';

describe('finalizeTriage — validate + enrich + dedupe + rank', () => {
  const findings = [
    {
      id: 'n1',
      type: 'nuclei',
      host: 'app.example.com',
      severity: 'critical',
      title: 'RCE',
      ref: 'CVE-1',
    },
    {
      id: 'n2',
      type: 'nuclei',
      host: 'app.example.com',
      severity: 'informational',
      title: 'TLS 1.0',
    },
    {
      id: 'h1',
      type: 'header',
      host: 'app.example.com',
      severity: 'low',
      title: 'Missing CSP',
    },
  ];

  it('ranks by severity, attaches gate confidence, and keeps report-worthy findings', () => {
    const { ranked, reportworthy, summary } = finalizeTriage(findings);
    expect(ranked[0].title).toBe('RCE');
    expect(ranked[0].rank).toBe(1);
    expect(ranked[0].confidence).toBe(75); // nuclei via the gate
    // default report threshold (55): both nuclei pass, the header (35) drops.
    expect(reportworthy.map((f) => f.title)).toEqual(['RCE', 'TLS 1.0']);
    expect(summary.total).toBe(3);
  });

  it('enriches findings with CWE/CVSS where a class exists', () => {
    const { ranked } = finalizeTriage([
      {
        id: 'h1',
        type: 'header',
        host: 'a.example.com',
        severity: 'low',
        title: 'H',
      },
    ]);
    expect(ranked[0].cwe).toBe('CWE-693'); // header enrichment is additive
  });

  it('dedupes duplicate findings', () => {
    const dup = {
      id: 'n1',
      type: 'nuclei',
      host: 'app.example.com',
      severity: 'high',
      title: 'X',
    };
    expect(finalizeTriage([dup, { ...dup }]).ranked).toHaveLength(1);
  });

  it('honors a custom minConfidence and tolerates a non-array', () => {
    const only = [
      {
        id: 'h1',
        type: 'header',
        host: 'a.example.com',
        severity: 'low',
        title: 'H',
      },
    ];
    expect(
      finalizeTriage(only, { minConfidence: 0 }).reportworthy
    ).toHaveLength(1);
    expect(
      finalizeTriage(only, { minConfidence: 90 }).reportworthy
    ).toHaveLength(0);
    expect(finalizeTriage(null).ranked).toEqual([]);
  });
});
