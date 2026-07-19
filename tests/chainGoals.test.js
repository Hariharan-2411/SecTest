import { describe, it, expect } from '@jest/globals';
import { LINK_PROBE_HINTS, deriveChainGoals } from '../src/utils/chainGoals';
import { ACTION_VERBS } from '../src/utils/escalation';

const scope = { inScope: ['*.example.com', 'example.com'], outOfScope: [] };

// Explicit confidence so the eligibility gate reads it directly (>= tentative 30).
const domXss = { id: 'x', type: 'dom-xss', severity: 'medium', host: 'app.example.com', title: 'XSS', confidence: 60 };
const jwt = { id: 's', type: 'jwt', severity: 'high', host: 'app.example.com', title: 'JWT', confidence: 70 };

describe('LINK_PROBE_HINTS', () => {
  it('every hint verb is a real escalation action verb', () => {
    const verbs = new Set(Object.keys(ACTION_VERBS));
    for (const [type, hint] of Object.entries(LINK_PROBE_HINTS)) {
      expect(Array.isArray(hint.verbs)).toBe(true);
      expect(hint.verbs.length).toBeGreaterThanOrEqual(1);
      for (const v of hint.verbs) {
        expect(verbs.has(v)).toBe(true); // hint for "${type}" names a non-verb otherwise
      }
      expect(typeof hint.note).toBe('string');
    }
  });
});

describe('deriveChainGoals', () => {
  it('surfaces a goal when the finding fills a link of a partial playbook', () => {
    const goals = deriveChainGoals(domXss, { findings: [domXss], scope });
    const g = goals.find((x) => x.playbookId === 'xss-secret-ato');
    expect(g).toBeTruthy();
    expect(g.have).toContain('dom-xss');
    const tokenLink = g.missing.find((m) => m.types.includes('jwt'));
    expect(tokenLink).toBeTruthy();
    expect(tokenLink.hint.verbs).toContain('deep_js'); // secret -> deep_js
  });

  it('returns [] when the finding is part of no partial playbook', () => {
    const lone = { id: 'z', type: 'informational-note', severity: 'informational', host: 'app.example.com', confidence: 60 };
    expect(deriveChainGoals(lone, { findings: [lone], scope })).toEqual([]);
  });

  it('excludes a playbook that is already complete', () => {
    // domXss + jwt COMPLETES xss-secret-ato -> it must not appear as a goal,
    // but xss-weak-csp (csp link still missing) should still be a goal.
    const goals = deriveChainGoals(domXss, { findings: [domXss, jwt], scope });
    expect(goals.find((g) => g.playbookId === 'xss-secret-ato')).toBeFalsy();
    expect(goals.find((g) => g.playbookId === 'xss-weak-csp')).toBeTruthy();
  });

  it('excludes an out-of-scope finding', () => {
    const out = { ...domXss, host: 'evil.test' };
    expect(deriveChainGoals(out, { findings: [out], scope })).toEqual([]);
  });

  it('excludes a noise-band finding (confidence < 30)', () => {
    const noisy = { ...domXss, confidence: 10 };
    expect(deriveChainGoals(noisy, { findings: [noisy], scope })).toEqual([]);
  });

  it('honors the max bound', () => {
    // domXss fills a link in two partial playbooks (xss-secret-ato, xss-weak-csp);
    // max:1 must cap the result.
    const goals = deriveChainGoals(domXss, { findings: [domXss], scope, max: 1 });
    expect(goals).toHaveLength(1);
  });

  it('never throws on garbage input', () => {
    expect(() => deriveChainGoals(null)).not.toThrow();
    expect(deriveChainGoals(null)).toEqual([]);
    expect(deriveChainGoals({}, {})).toEqual([]);
    expect(deriveChainGoals(domXss, { findings: 'nope', scope })).toEqual([]);
  });
});
