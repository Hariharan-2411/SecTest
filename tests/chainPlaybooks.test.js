import { describe, it, expect } from '@jest/globals';
import { PLAYBOOKS, matchPlaybooks } from '../src/utils/chainPlaybooks';

const scope = { inScope: ['*.example.com', 'example.com'], outOfScope: [] };

// Findings carry explicit confidence so getConfidence reads it directly (no scoring).
const domXss = { id: 'x', type: 'dom-xss', severity: 'medium', host: 'app.example.com', title: 'XSS', confidence: 60 };
const jwt = { id: 's', type: 'jwt', severity: 'high', host: 'app.example.com', title: 'JWT', confidence: 70 };
const cors = { id: 'c', type: 'permissive-cors', severity: 'high', host: 'app.example.com', title: 'CORS', confidence: 70 };
const cookie = { id: 'k', type: 'set-cookie', severity: 'low', host: 'app.example.com', title: 'Cookie', confidence: 40 };

describe('PLAYBOOKS', () => {
  it('are well-formed: id, name, and >= 2 links each with any-of type lists', () => {
    expect(PLAYBOOKS.length).toBeGreaterThanOrEqual(5);
    for (const p of PLAYBOOKS) {
      expect(typeof p.id).toBe('string');
      expect(typeof p.name).toBe('string');
      expect(Array.isArray(p.links)).toBe(true);
      expect(p.links.length).toBeGreaterThanOrEqual(2);
      for (const l of p.links) {
        expect(typeof l.id).toBe('string');
        expect(Array.isArray(l.match.types)).toBe(true);
        expect(l.match.types.length).toBeGreaterThanOrEqual(1);
      }
    }
  });

  it('each playbook has pairwise-disjoint link type-sets (the greedy matcher assumes this)', () => {
    for (const p of PLAYBOOKS) {
      const seen = new Map(); // type -> linkId that first claimed it
      for (const l of p.links) {
        for (const t of l.match.types) {
          expect(seen.has(t)).toBe(false); // a type must not appear in two links of one playbook
          seen.set(t, l.id);
        }
      }
    }
  });
});

describe('matchPlaybooks', () => {
  it('reports a complete match with grounded links and a derived severity', () => {
    const res = matchPlaybooks([domXss, jwt], { scope });
    const m = res.find((r) => r.playbookId === 'xss-secret-ato');
    expect(m).toBeTruthy();
    expect(m.complete).toBe(true);
    expect(m.completeness).toBe(1);
    expect(m.missing).toEqual([]);
    const byLink = Object.fromEntries(m.satisfied.map((s) => [s.linkId, s.findingId]));
    expect(byLink.xss).toBe('x');
    expect(byLink.token).toBe('s');
    // deriveSeverity bumps the strongest (high) one level -> critical
    expect(m.severity).toBe('critical');
  });

  it('reports missing links for a partial match', () => {
    const res = matchPlaybooks([domXss], { scope });
    const m = res.find((r) => r.playbookId === 'xss-secret-ato');
    expect(m).toBeTruthy();
    expect(m.complete).toBe(false);
    expect(m.completeness).toBeCloseTo(0.5);
    expect(m.missing.map((x) => x.linkId)).toContain('token');
    expect(m.missing[0]).toHaveProperty('label');
    expect(m.missing[0]).toHaveProperty('match');
  });

  it('excludes an out-of-scope finding from filling a link', () => {
    const outHost = { ...jwt, id: 's2', host: 'evil.test' };
    const res = matchPlaybooks([domXss, outHost], { scope });
    const m = res.find((r) => r.playbookId === 'xss-secret-ato');
    expect(m.complete).toBe(false); // token link unfilled — evil.test is out of scope
  });

  it('excludes a noise-band finding (confidence < 30)', () => {
    const noisy = { ...jwt, id: 's3', confidence: 10 };
    const res = matchPlaybooks([domXss, noisy], { scope });
    const m = res.find((r) => r.playbookId === 'xss-secret-ato');
    expect(m.complete).toBe(false);
  });

  it('matches a second playbook (cors-cookie-theft) from real header types', () => {
    const res = matchPlaybooks([cors, cookie], { scope });
    const m = res.find((r) => r.playbookId === 'cors-cookie-theft');
    expect(m).toBeTruthy();
    expect(m.complete).toBe(true);
  });

  it('never fills two links with the same finding, and returns [] for no eligible findings', () => {
    expect(matchPlaybooks([], { scope })).toEqual([]);
    // a lone dom-xss can satisfy only the xss link of xss-secret-ato, never both
    const res = matchPlaybooks([domXss], { scope });
    const m = res.find((r) => r.playbookId === 'xss-secret-ato');
    expect(m.satisfied).toHaveLength(1);
  });

  it('sorts complete matches ahead of partial ones', () => {
    const res = matchPlaybooks([domXss, jwt, cors], { scope });
    // xss-secret-ato is complete; cors-* is partial (only cors present) -> complete first
    const completeIdx = res.findIndex((r) => r.complete);
    const partialIdx = res.findIndex((r) => !r.complete);
    if (partialIdx !== -1) expect(completeIdx).toBeLessThan(partialIdx);
  });

  it('does not throw on garbage input', () => {
    expect(() => matchPlaybooks(null)).not.toThrow();
    expect(matchPlaybooks(null)).toEqual([]);
    expect(() => matchPlaybooks([null, undefined, {}], {})).not.toThrow();
  });
});
