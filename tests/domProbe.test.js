import { describe, it, expect } from '@jest/globals';
import { buildDomProbe, classifyProbeResult } from '../src/utils/domProbe';
import { scoreFinding } from '../src/utils/validate';

describe('buildDomProbe', () => {
  it('builds a canary descriptor from a DOM-XSS finding with a supported sink + source', () => {
    const p = buildDomProbe({ id: 'f1', type: 'dom-xss', sink: 'innerHTML', sources: ['location.hash'] });
    expect(p).toBeTruthy();
    expect(p.canary).toMatch(/^IRIS_CANARY_/);
    expect(p.source).toBe('location.hash');
    expect(p.sink).toBe('innerHTML');
    expect(p.findingId).toBe('f1');
  });

  it('normalizes sink and source variants', () => {
    const p = buildDomProbe({ type: 'dom-xss', sink: 'document.write()', sources: ['window.name'] });
    expect(p.sink).toBe('document.write');
    expect(p.source).toBe('window.name');
  });

  it('returns null for an unsupported sink', () => {
    expect(buildDomProbe({ type: 'dom-xss', sink: 'textContent', sources: ['location.hash'] })).toBeNull();
  });

  it('returns null when no supported source is present', () => {
    expect(buildDomProbe({ type: 'dom-xss', sink: 'innerHTML', sources: ['document.cookie'] })).toBeNull();
  });

  it('returns null for a non-DOM-XSS finding', () => {
    expect(buildDomProbe({ type: 'sqli-boolean', sink: 'innerHTML', sources: ['location.hash'] })).toBeNull();
    expect(buildDomProbe(null)).toBeNull();
  });

  it('mints a unique canary per call', () => {
    const a = buildDomProbe({ type: 'dom-xss', sink: 'eval', sources: ['location.hash'] });
    const b = buildDomProbe({ type: 'dom-xss', sink: 'eval', sources: ['location.hash'] });
    expect(a.canary).not.toBe(b.canary);
  });
});

describe('classifyProbeResult', () => {
  it('confirms when the canary reached the sink unescaped', () => {
    const r = classifyProbeResult({ reachedSink: true, unescaped: true, sinkType: 'innerHTML' }, { canary: 'IRIS_CANARY_x' });
    expect(r.confirmed).toBe(true);
    expect(r.evidence).toMatch(/innerHTML/);
  });

  it('does not confirm when the canary was escaped/encoded', () => {
    const r = classifyProbeResult({ reachedSink: true, unescaped: false }, { canary: 'x' });
    expect(r.confirmed).toBe(false);
  });

  it('does not confirm when the canary never reached the sink, and never throws', () => {
    expect(classifyProbeResult({ reachedSink: false }, {}).confirmed).toBe(false);
    expect(() => classifyProbeResult(null)).not.toThrow();
    expect(classifyProbeResult(null).confirmed).toBe(false);
  });
});

describe('probeConfirmed raises DOM-XSS confidence (validate bonus)', () => {
  it('a runtime-confirmed DOM-XSS scores higher than the same finding unconfirmed', () => {
    const base = { type: 'dom-xss', reflection: 'attribute' };
    const confirmed = { ...base, probeConfirmed: true };
    expect(scoreFinding(confirmed).confidence).toBeGreaterThan(scoreFinding(base).confidence);
  });
});
