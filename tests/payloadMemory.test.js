import { describe, it, expect } from '@jest/globals';
import { memoryKey, recordSuccess, recallPayloads } from '../src/utils/payloadMemory';

const ctx = { framework: 'React', sink: 'innerHTML', vulnerability: 'XSS' };

describe('memoryKey', () => {
  it('is stable and case-insensitive from framework + sink + vulnerability', () => {
    expect(memoryKey(ctx)).toBe(memoryKey({ framework: 'react', sink: 'INNERHTML', vulnerability: 'xss' }));
    expect(memoryKey({})).toBe('any|any|any');
  });
});

describe('recordSuccess', () => {
  it('records a winning payload under its context key', () => {
    const mem = recordSuccess({}, ctx, '<img src=x onerror=1>');
    expect(recallPayloads(mem, ctx)).toContain('<img src=x onerror=1>');
  });

  it('bumps the count instead of duplicating the same payload', () => {
    let mem = recordSuccess({}, ctx, 'P');
    mem = recordSuccess(mem, ctx, 'P');
    const bucket = mem[memoryKey(ctx)];
    expect(bucket).toHaveLength(1);
    expect(bucket[0].count).toBe(2);
  });

  it('returns a NEW memory object (does not mutate the input)', () => {
    const input = {};
    const out = recordSuccess(input, ctx, 'P');
    expect(input).toEqual({});
    expect(out).not.toBe(input);
  });

  it('never throws on garbage and ignores empty payloads', () => {
    expect(() => recordSuccess(null, null, null)).not.toThrow();
    expect(recordSuccess({}, ctx, '   ')).toEqual({}); // blank payload not recorded
  });
});

describe('recallPayloads', () => {
  it('orders by count desc and honors the limit', () => {
    let mem = {};
    mem = recordSuccess(mem, ctx, 'A');
    mem = recordSuccess(mem, ctx, 'B');
    mem = recordSuccess(mem, ctx, 'B'); // B now count 2
    expect(recallPayloads(mem, ctx)[0]).toBe('B');
    expect(recallPayloads(mem, ctx, { limit: 1 })).toEqual(['B']);
  });

  it('returns [] for an unknown context and never throws', () => {
    expect(recallPayloads({}, { framework: 'Vue' })).toEqual([]);
    expect(() => recallPayloads(null, null)).not.toThrow();
  });
});
