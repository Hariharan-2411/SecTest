import { describe, it, expect } from '@jest/globals';
import { buildReconDigest, formatReconDigest } from '../src/utils/reconDigest';

const scope = { inScope: ['*.example.com', 'example.com'], outOfScope: [] };
const jwt = { id: 's', type: 'jwt', severity: 'high', host: 'app.example.com', title: 'Exposed JWT', confidence: 70 };
const hsts = { id: 'h', type: 'missing-hsts', severity: 'low', host: 'app.example.com', title: 'No HSTS', confidence: 35 };

describe('buildReconDigest', () => {
  it('counts new surface and ranks high-signal findings as top moves', () => {
    const d = buildReconDigest(
      { newHosts: ['new.example.com'], newEndpoints: ['/api/x'], newFindings: [hsts, jwt] },
      { scope }
    );
    expect(d.empty).toBe(false);
    expect(d.counts).toEqual({ hosts: 1, endpoints: 1, findings: 2 });
    expect(d.summary).toMatch(/1 new host/);
    // the exposed JWT is high-signal; the missing-HSTS is not → JWT leads
    expect(d.topMoves[0].findingId).toBe('s');
    expect(d.topMoves.some((m) => m.findingId === 'h')).toBe(false);
  });

  it('reports an empty delta cleanly', () => {
    const d = buildReconDigest({}, { scope });
    expect(d.empty).toBe(true);
    expect(d.summary).toMatch(/no new/i);
    expect(d.topMoves).toEqual([]);
  });

  it('analyzes new findings in the context of all findings when provided', () => {
    // a new graphql-surface completes a chain-link only alongside the existing introspection finding
    const intro = { id: 'gi', type: 'graphql-introspection', severity: 'medium', host: 'app.example.com', confidence: 60, title: 'intro' };
    const surface = { id: 'gs', type: 'graphql-surface', severity: 'low', host: 'app.example.com', confidence: 50, title: 'surface' };
    const d = buildReconDigest({ newFindings: [surface] }, { scope, allFindings: [intro, surface] });
    // only the NEW finding (gs) is surfaced, but its chain-link status comes from the full set
    expect(d.topMoves.every((m) => m.findingId === 'gs')).toBe(true);
    expect(d.topMoves[0].chainLink).toBe(true);
  });

  it('never throws on garbage', () => {
    expect(() => buildReconDigest(null, null)).not.toThrow();
    expect(buildReconDigest(null).empty).toBe(true);
  });
});

describe('formatReconDigest', () => {
  it('formats a text digest with the summary, new hosts, and top moves', () => {
    const d = buildReconDigest({ newHosts: ['new.example.com'], newFindings: [jwt] }, { scope });
    const text = formatReconDigest(d);
    expect(text).toMatch(/Recon/);
    expect(text).toContain('new.example.com');
    expect(text).toContain('Exposed JWT');
  });
  it('formats the empty case and never throws', () => {
    expect(() => formatReconDigest(null)).not.toThrow();
    expect(formatReconDigest(buildReconDigest({}, { scope }))).toMatch(/no new/i);
  });
});
