import { describe, it, expect } from '@jest/globals';
import {
  compareResponses,
  classifyDifferential,
  classifyTiming,
  paramValue,
  buildVariantUrl,
  firstParam,
} from '../src/utils/oracle';

const R = (status, length, timeMs = 100) => ({ status, length, timeMs });

describe('compareResponses', () => {
  it('flags a status difference', () => {
    expect(compareResponses(R(200, 500), R(500, 500)).differs).toBe(true);
  });
  it('flags a large length difference', () => {
    expect(compareResponses(R(200, 5000), R(200, 500)).differs).toBe(true);
  });
  it('ignores tiny length noise', () => {
    expect(compareResponses(R(200, 510), R(200, 500)).differs).toBe(false);
  });
  it('reports the raw deltas', () => {
    const s = compareResponses(R(200, 600, 300), R(404, 500, 100)).signals;
    expect(s).toEqual({ statusDelta: -204, lengthDelta: 100, timeDelta: 200 });
  });
  it('handles missing samples', () => {
    expect(compareResponses(null, R(200, 1)).differs).toBe(false);
  });
});

describe('classifyDifferential', () => {
  it('returns none when truthy and falsy match', () => {
    const r = classifyDifferential({ truthy: R(200, 500), falsy: R(200, 500) });
    expect(r.signal).toBe('none');
    expect(r.confidence).toBe(0);
  });
  it('flags boolean signal when truthy and falsy diverge', () => {
    const r = classifyDifferential({ truthy: R(200, 5000), falsy: R(200, 500) });
    expect(r.signal).toBe('boolean');
    expect(r.confidence).toBeGreaterThanOrEqual(0.5);
  });
  it('raises confidence for the textbook shape (truthy~base, falsy≠base)', () => {
    const r = classifyDifferential({
      base: R(200, 500),
      truthy: R(200, 500),
      falsy: R(200, 50),
    });
    expect(r.signal).toBe('boolean');
    expect(r.confidence).toBeGreaterThanOrEqual(0.8);
  });
});

describe('classifyTiming', () => {
  it('flags a clear delay', () => {
    const r = classifyTiming({ base: R(200, 500, 120), delayed: R(200, 500, 5200) });
    expect(r.signal).toBe('time');
    expect(r.confidence).toBeGreaterThanOrEqual(0.65);
  });
  it('ignores small timing noise', () => {
    const r = classifyTiming({ base: R(200, 500, 120), delayed: R(200, 500, 300) });
    expect(r.signal).toBe('none');
  });
  it('handles missing samples', () => {
    expect(classifyTiming({ base: R(200, 1, 1) }).signal).toBe('none');
  });
});

describe('URL helpers', () => {
  it('reads a param value', () => {
    expect(paramValue('https://x.com/p?id=7&q=a', 'id')).toBe('7');
    expect(paramValue('https://x.com/p', 'id')).toBe('');
  });
  it('sets a param, adding it when absent', () => {
    expect(buildVariantUrl('https://x.com/p?id=7', 'id', "7' AND '1'='1")).toContain('id=7');
    expect(buildVariantUrl('https://x.com/p', 'test', 'v')).toContain('test=v');
  });
  it('does not mutate for bad input', () => {
    expect(buildVariantUrl('not a url', 'id', 'v')).toBe('not a url');
  });
  it('finds the first param name', () => {
    expect(firstParam('https://x.com/p?a=1&b=2')).toBe('a');
    expect(firstParam('https://x.com/p')).toBe('');
  });
});
