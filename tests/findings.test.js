import { describe, it, expect } from '@jest/globals';
import {
  normalizeFinding,
  upsertFinding,
  upsertFindings,
  dedupeFindings,
  sortFindings,
  summarizeFindings,
  toReportFinding,
  deriveSeverity,
} from '../src/utils/findings';

describe('normalizeFinding', () => {
  it('fills defaults and stamps timestamps', () => {
    const f = normalizeFinding({ title: 'X', type: 'header' }, '2026-01-01T00:00:00Z');
    expect(f).toMatchObject({ title: 'X', type: 'header', severity: 'medium', firstSeen: '2026-01-01T00:00:00Z' });
    expect(f.id).toBeTruthy();
  });
  it('preserves DOM-XSS display fields', () => {
    const f = normalizeFinding({ type: 'dom-xss', sink: 'innerHTML', sources: ['location'] });
    expect(f.sink).toBe('innerHTML');
    expect(f.sources).toEqual(['location']);
  });
});

describe('upsertFinding', () => {
  it('adds a new finding', () => {
    const out = upsertFinding([], { id: 'a', severity: 'low' });
    expect(out).toHaveLength(1);
  });
  it('updates in place and preserves firstSeen', () => {
    const first = upsertFinding([], { id: 'a', severity: 'low' }, '2026-01-01T00:00:00Z');
    const second = upsertFinding(first, { id: 'a', severity: 'high' }, '2026-02-01T00:00:00Z');
    expect(second).toHaveLength(1);
    expect(second[0].severity).toBe('high');
    expect(second[0].firstSeen).toBe('2026-01-01T00:00:00Z');
    expect(second[0].updatedAt).toBe('2026-02-01T00:00:00Z');
  });
  it('upsertFindings merges a batch', () => {
    const out = upsertFindings([], [{ id: 'a' }, { id: 'b' }, { id: 'a' }]);
    expect(out).toHaveLength(2);
  });
});

describe('dedupeFindings', () => {
  it('keeps per-host distinct by default', () => {
    const list = [
      { id: 'missing-csp', host: 'a.x.com', severity: 'medium' },
      { id: 'missing-csp', host: 'b.x.com', severity: 'medium' },
    ];
    expect(dedupeFindings(list)).toHaveLength(2);
  });
  it('collapses across hosts with crossHost and keeps higher severity', () => {
    const list = [
      { id: 'missing-csp', host: 'a.x.com', severity: 'low' },
      { id: 'missing-csp', host: 'b.x.com', severity: 'high' },
    ];
    const out = dedupeFindings(list, { crossHost: true });
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe('high');
  });
});

describe('sortFindings / summarizeFindings', () => {
  it('sorts by severity then confidence', () => {
    const out = sortFindings([
      { severity: 'low', confidence: 0.9 },
      { severity: 'high', confidence: 0.5 },
      { severity: 'high', confidence: 0.8 },
    ]);
    expect(out.map((f) => f.severity)).toEqual(['high', 'high', 'low']);
    expect(out[0].confidence).toBe(0.8);
  });
  it('counts by severity', () => {
    const c = summarizeFindings([{ severity: 'high' }, { severity: 'high' }, { severity: 'low' }]);
    expect(c).toMatchObject({ high: 2, low: 1, total: 3 });
  });
});

describe('toReportFinding', () => {
  it('maps into the report builder shape', () => {
    const r = toReportFinding({ title: 'SQLi', host: 'x.com', severity: 'high', ref: 'CWE-89', evidence: 'delta' });
    expect(r).toEqual({ title: 'SQLi', target: 'x.com', severity: 'high', ref: 'CWE-89', summary: 'delta', evidence: 'delta' });
  });
});

describe('deriveSeverity (relocated from chains)', () => {
  it('bumps the strongest constituent one level, capped at critical', () => {
    expect(deriveSeverity([{ severity: 'medium' }, { severity: 'high' }])).toBe('critical');
    expect(deriveSeverity([{ severity: 'low' }, { severity: 'low' }])).toBe('medium');
    expect(deriveSeverity([{ severity: 'critical' }])).toBe('critical');
    expect(deriveSeverity([])).toBe('informational');
  });
});
