import { describe, it, expect } from '@jest/globals';
import { buildPayloadContext } from '../src/utils/payloadContext';

const vuln = { key: 'xss', label: 'Cross-Site Scripting (XSS)' };

describe('buildPayloadContext', () => {
  it('carries the vulnerability label and the payload test type', () => {
    const c = buildPayloadContext(vuln, {});
    expect(c.vulnerability).toBe('Cross-Site Scripting (XSS)');
    expect(c.testType).toBe('Payload Generation');
  });

  it('detects the framework from recon', () => {
    const c = buildPayloadContext(vuln, { recon: { frameworks: ['React', 'jQuery'] } });
    expect(c.framework).toContain('React');
  });

  it('extracts reflection context and sink from a dom-xss finding', () => {
    const findings = [{ type: 'dom-xss', reflection: 'attribute', sink: 'innerHTML' }];
    const c = buildPayloadContext(vuln, { findings });
    expect(c.reflectionContext).toBe('attribute');
    expect(c.sink).toBe('innerHTML');
  });

  it('prefers a dom-xss finding that actually carries context', () => {
    const findings = [
      { type: 'dom-xss', title: 'bare' },
      { type: 'dom-xss', reflection: 'js', sink: 'eval' },
    ];
    const c = buildPayloadContext(vuln, { findings });
    expect(c.reflectionContext).toBe('js');
    expect(c.sink).toBe('eval');
  });

  it('includes observed params from a single-host inventory', () => {
    const c = buildPayloadContext(vuln, { inventory: { params: ['id', 'q'] } });
    expect(c.params).toEqual(['id', 'q']);
  });

  it('keeps back-compat fields and sensible defaults with no sources', () => {
    const c = buildPayloadContext(vuln, {});
    expect(c.elementType).toBe('input');
    expect(c.elementName).toBe('*');
    expect(c.framework).toBe('');
    expect(c.reflectionContext).toBe('');
    expect(c.sink).toBe('');
    expect(c.params).toEqual([]);
  });

  it('accepts a string vuln and never throws on garbage', () => {
    expect(buildPayloadContext('sqli', {}).vulnerability).toBe('sqli');
    expect(() => buildPayloadContext(null, null)).not.toThrow();
    expect(buildPayloadContext(null, null).vulnerability).toBe('General testing');
  });
});
