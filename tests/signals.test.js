import { describe, it, expect } from '@jest/globals';
import { HIGH_SIGNAL_TYPES, detectEscalationSignals } from '../src/utils/signals';

const scope = { inScope: ['*.example.com', 'example.com'], outOfScope: [] };
const F = (o) => ({ severity: 'medium', host: 'app.example.com', ...o });

const gqlIntro = F({ id: 'gi', type: 'graphql-introspection', title: 'Introspection on', confidence: 60 });
const gqlSurface = F({ id: 'gs', type: 'graphql-surface', title: 'Surface', severity: 'low', confidence: 50 });
const cors = F({ id: 'c', type: 'permissive-cors', title: 'CORS', severity: 'high', confidence: 70 });
const cookie = F({ id: 'k', type: 'set-cookie', title: 'Cookie', severity: 'low', confidence: 40 });

describe('HIGH_SIGNAL_TYPES', () => {
  it('includes the exposed-surface and credential types', () => {
    expect(HIGH_SIGNAL_TYPES.has('api-spec-exposed')).toBe(true);
    expect(HIGH_SIGNAL_TYPES.has('graphql-introspection')).toBe(true);
    expect(HIGH_SIGNAL_TYPES.has('jwt')).toBe(true);
    expect(HIGH_SIGNAL_TYPES.has('permissive-cors')).toBe(true);
  });
});

describe('detectEscalationSignals', () => {
  it('flags a chain-link finding, with a chain reason naming the missing link', () => {
    const s = detectEscalationSignals([gqlIntro, gqlSurface], { scope });
    const g = s.find((x) => x.findingId === 'gi');
    expect(g).toBeTruthy();
    expect(g.chainLink).toBe(true);
    expect(g.reason).toMatch(/access-control/i); // the missing link's label
    expect(g.chainGoals.length).toBeGreaterThan(0);
  });

  it('flags a high-signal finding even when its chain is already complete', () => {
    // cors + cookie COMPLETES cors-cookie-theft → cors is not a chain-link here,
    // but permissive-cors is a high-signal type on its own.
    const s = detectEscalationSignals([cors, cookie], { scope });
    const c = s.find((x) => x.findingId === 'c');
    expect(c).toBeTruthy();
    expect(c.chainLink).toBe(false);
    expect(c.reason).toMatch(/CORS/i);
    // set-cookie is neither high-signal nor a partial chain → no suggestion
    expect(s.find((x) => x.findingId === 'k')).toBeFalsy();
  });

  it('excludes a noise-band finding', () => {
    const noisy = F({ id: 'n', type: 'dom-xss', title: 'maybe XSS', reflection: 'none' }); // scores 0 → noise
    expect(detectEscalationSignals([noisy], { scope })).toEqual([]);
  });

  it('excludes an out-of-scope finding', () => {
    const out = F({ id: 'o', type: 'jwt', title: 'JWT', host: 'evil.test', confidence: 70 });
    expect(detectEscalationSignals([out], { scope })).toEqual([]);
  });

  it('yields nothing for a plain, non-signal finding', () => {
    const plain = F({ id: 'p', type: 'missing-hsts', title: 'No HSTS', severity: 'low' });
    expect(detectEscalationSignals([plain], { scope })).toEqual([]);
  });

  it('ranks chain-links ahead of high-signal-only, and honors max', () => {
    const s = detectEscalationSignals([gqlIntro, gqlSurface, cors, cookie], { scope });
    expect(s[0].findingId).toBe('gi'); // chain-link first
    const capped = detectEscalationSignals([gqlIntro, gqlSurface, cors, cookie], { scope, max: 1 });
    expect(capped).toHaveLength(1);
    expect(capped[0].findingId).toBe('gi');
  });

  it('never throws on garbage input', () => {
    expect(() => detectEscalationSignals(null)).not.toThrow();
    expect(detectEscalationSignals(null)).toEqual([]);
    expect(detectEscalationSignals([null, undefined, {}], {})).toEqual([]);
  });
});
