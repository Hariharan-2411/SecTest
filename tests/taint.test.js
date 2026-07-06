import { describe, it, expect } from '@jest/globals';
import { sinkToCandidate, taintFindings } from '../src/utils/taint';

const sink = (o) => ({ sink: 'innerHTML', line: 1, snippet: 'el.innerHTML = x', sources: [], ...o });

describe('sinkToCandidate', () => {
  it('returns null for an untainted sink (no sources)', () => {
    expect(sinkToCandidate(sink({ sources: [] }))).toBeNull();
  });

  it('produces a dom-xss finding for a tainted high-danger sink', () => {
    const c = sinkToCandidate(sink({ sink: 'innerHTML', sources: ['location'] }), 'x.com');
    expect(c).toMatchObject({ type: 'dom-xss', host: 'x.com', ref: 'CWE-79', sink: 'innerHTML' });
    expect(c.severity).toBe('medium'); // high-danger sink + direct source
    expect(c.confidence).toBeGreaterThanOrEqual(0.9);
    expect(c.title).toContain('location');
  });

  it('rates an indirect source lower and as low severity', () => {
    const c = sinkToCandidate(sink({ sink: 'innerHTML', sources: ['URLSearchParams'] }));
    expect(c.severity).toBe('low');
    expect(c.confidence).toBeLessThan(0.9);
  });

  it('treats a navigation sink as lower base danger', () => {
    const direct = sinkToCandidate(sink({ sink: 'innerHTML', sources: ['location'] }));
    const nav = sinkToCandidate(sink({ sink: 'location.assign', snippet: 'location = h', sources: ['location'] }));
    expect(nav.confidence).toBeLessThan(direct.confidence);
    expect(nav.severity).toBe('low'); // not in HIGH_DANGER set
  });
});

describe('taintFindings', () => {
  it('filters untainted sinks and ranks by confidence desc', () => {
    const sinks = [
      sink({ sink: 'location.assign', snippet: 'a', sources: ['URLSearchParams'] }), // low
      sink({ sink: 'eval', snippet: 'b', sources: ['location'] }),                    // high
      sink({ sink: 'innerHTML', snippet: 'c', sources: [] }),                         // dropped
    ];
    const out = taintFindings(sinks, 'x.com');
    expect(out).toHaveLength(2);
    expect(out[0].sink).toBe('eval');
    expect(out[0].confidence).toBeGreaterThan(out[1].confidence);
  });

  it('dedupes identical candidates', () => {
    const s = sink({ sink: 'eval', snippet: 'same', sources: ['location'] });
    expect(taintFindings([s, { ...s }], 'x.com')).toHaveLength(1);
  });

  it('handles non-array input safely', () => {
    expect(taintFindings(null)).toEqual([]);
    expect(taintFindings(undefined)).toEqual([]);
  });
});
