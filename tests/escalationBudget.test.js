import { describe, it, expect } from '@jest/globals';
import { escalationBudgetFor, BAND_PLAN } from '../src/utils/escalationBudget';
import { MAX_DEPTH, DEFAULT_ESCALATION_BUDGET } from '../src/utils/escalation';

describe('escalationBudgetFor', () => {
  it('gives a confirmed finding the deepest plan and most budget', () => {
    const plan = escalationBudgetFor({ type: 'private_key' }); // scores 85 → confirmed
    expect(plan.maxDepth).toBeGreaterThan(MAX_DEPTH);
    expect(plan.budget).toBeGreaterThanOrEqual(DEFAULT_ESCALATION_BUDGET);
  });

  it('gives a likely finding the defaults', () => {
    const plan = escalationBudgetFor({ type: 'nuclei' }); // scores 75 → likely
    expect(plan.maxDepth).toBe(MAX_DEPTH);
    expect(plan.budget).toBe(DEFAULT_ESCALATION_BUDGET);
  });

  it('gives a tentative finding a shallow, cheap plan', () => {
    const plan = escalationBudgetFor({ type: 'header' }); // scores 35 → tentative
    expect(plan.maxDepth).toBeLessThan(MAX_DEPTH);
    expect(plan.maxDepth).toBeGreaterThanOrEqual(1);
    expect(plan.budget).toBeLessThan(DEFAULT_ESCALATION_BUDGET);
  });

  it('gives a noise finding no plan', () => {
    const plan = escalationBudgetFor({ type: 'dom-xss', reflection: 'none' }); // scores 0 → noise
    expect(plan.maxDepth).toBe(0);
    expect(plan.budget).toBe(0);
  });

  it('treats garbage as an unknown (tentative) finding and never throws', () => {
    expect(() => escalationBudgetFor(null)).not.toThrow();
    // scoreFinding({}) → unknown type → tentative band → the shallow, cheap plan
    expect(escalationBudgetFor(null)).toEqual(BAND_PLAN.tentative);
  });
});
