import { describe, it, expect } from '@jest/globals';
import {
  createProgram,
  createSubmission,
  summarizeSubmissions,
  summarizeByProgram,
  PLATFORMS,
  SUBMISSION_STATES,
} from '../src/utils/programs';

describe('createProgram', () => {
  it('creates a normalized program with an id', () => {
    const p = createProgram({ name: '  Acme  ', platform: 'HackerOne' });
    expect(p.id).toMatch(/^prog_/);
    expect(p.name).toBe('Acme');
    expect(p.platform).toBe('HackerOne');
  });
  it('falls back to Other for unknown platforms', () => {
    expect(createProgram({ name: 'x', platform: 'Nope' }).platform).toBe('Other');
  });
});

describe('createSubmission', () => {
  it('defaults state to draft and bounty to 0', () => {
    const s = createSubmission({ programId: 'p1', title: 'XSS' });
    expect(s.state).toBe('draft');
    expect(s.bounty).toBe(0);
  });
  it('keeps a positive bounty', () => {
    expect(createSubmission({ programId: 'p1', title: 'x', bounty: 500 }).bounty).toBe(500);
  });
  it('ignores an invalid bounty', () => {
    expect(createSubmission({ programId: 'p1', title: 'x', bounty: 'abc' }).bounty).toBe(0);
  });
});

describe('summarizeSubmissions', () => {
  it('sums earnings from paid only and counts pipeline', () => {
    const subs = [
      createSubmission({ programId: 'p', title: 'a', state: 'paid', bounty: 500 }),
      createSubmission({ programId: 'p', title: 'b', state: 'paid', bounty: 250 }),
      createSubmission({ programId: 'p', title: 'c', state: 'submitted', bounty: 999 }),
      createSubmission({ programId: 'p', title: 'd', state: 'duplicate', bounty: 100 }),
    ];
    const sum = summarizeSubmissions(subs);
    expect(sum.earned).toBe(750); // paid only, not the submitted 999
    expect(sum.paidCount).toBe(2);
    expect(sum.pipeline).toBe(1); // only the 'submitted' one is open
    expect(sum.total).toBe(4);
    expect(sum.counts.paid).toBe(2);
  });
  it('handles an empty list', () => {
    expect(summarizeSubmissions([])).toMatchObject({ earned: 0, pipeline: 0, total: 0 });
  });
});

describe('summarizeByProgram', () => {
  it('rolls submissions up under their program', () => {
    const p1 = createProgram({ name: 'One' });
    const p2 = createProgram({ name: 'Two' });
    const subs = [
      createSubmission({ programId: p1.id, title: 'a', state: 'paid', bounty: 100 }),
      createSubmission({ programId: p1.id, title: 'b', state: 'submitted' }),
    ];
    const rolled = summarizeByProgram([p1, p2], subs);
    const one = rolled.find((p) => p.id === p1.id);
    const two = rolled.find((p) => p.id === p2.id);
    expect(one.submissionCount).toBe(2);
    expect(one.summary.earned).toBe(100);
    expect(two.submissionCount).toBe(0);
  });
});

describe('constants', () => {
  it('expose expected platforms and states', () => {
    expect(PLATFORMS).toContain('HackerOne');
    expect(SUBMISSION_STATES).toContain('paid');
  });
});
