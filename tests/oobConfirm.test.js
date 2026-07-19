import { describe, it, expect } from '@jest/globals';
import { classifyOobInteractions, markOobResult } from '../src/utils/oobConfirm';

describe('classifyOobInteractions', () => {
  it('is unconfirmed with no interactions', () => {
    const r = classifyOobInteractions([], { cid: 'abc' });
    expect(r.confirmed).toBe(false);
    expect(r.hitCount).toBe(0);
  });

  it('confirms a blind bug on the first out-of-band interaction', () => {
    const r = classifyOobInteractions([{ method: 'GET', ip: '1.2.3.4' }], { cid: 'abc' });
    expect(r.confirmed).toBe(true);
    expect(r.hitCount).toBe(1);
    expect(r.evidence).toMatch(/confirmed/i);
  });

  it('counts multiple interactions and dedupes kinds', () => {
    const r = classifyOobInteractions(
      [{ protocol: 'dns' }, { protocol: 'dns' }, { protocol: 'http' }],
      { cid: 'abc' }
    );
    expect(r.hitCount).toBe(3);
    expect(r.evidence).toMatch(/dns/);
    expect(r.evidence).toMatch(/http/);
  });

  it('never throws on garbage input', () => {
    expect(() => classifyOobInteractions(null)).not.toThrow();
    expect(classifyOobInteractions(null).confirmed).toBe(false);
    expect(classifyOobInteractions([null, undefined]).hitCount).toBe(0);
  });
});

describe('markOobResult', () => {
  it('sets oobHit true on a confirmed result, preserving the finding', () => {
    const f = { id: 'f1', type: 'oob', title: 'blind SSRF' };
    const out = markOobResult(f, { confirmed: true, hitCount: 2 });
    expect(out.oobHit).toBe(true);
    expect(out.oobHitCount).toBe(2);
    expect(out.id).toBe('f1');
    expect(out.title).toBe('blind SSRF');
  });

  it('sets oobHit false on an unconfirmed result and never throws on garbage', () => {
    expect(markOobResult({ id: 'x' }, { confirmed: false }).oobHit).toBe(false);
    expect(() => markOobResult(null, null)).not.toThrow();
    expect(markOobResult(null, null).oobHit).toBe(false);
  });
});
