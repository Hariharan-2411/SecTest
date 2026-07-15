import { describe, it, expect } from '@jest/globals';
import {
  cvssBaseScore,
  cvssSeverity,
  enrichFinding,
  enrichFindings,
  CLASS_META,
} from '../src/utils/enrich';

describe('cvssBaseScore — official CVSS 3.1 formula', () => {
  it('computes known vectors to their published base scores', () => {
    expect(cvssBaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBe(
      9.8
    );
    expect(cvssBaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N')).toBe(
      6.1
    ); // reflected XSS
  });

  it('returns 0 for an invalid or missing vector', () => {
    expect(cvssBaseScore('not a vector')).toBe(0);
    expect(cvssBaseScore('CVSS:3.1/AV:N')).toBe(0); // incomplete
    expect(cvssBaseScore(null)).toBe(0);
  });
});

describe('cvssSeverity — CVSS 3.1 bands', () => {
  it('maps scores onto the qualitative bands at the boundaries', () => {
    expect(cvssSeverity(0)).toBe('none');
    expect(cvssSeverity(0.1)).toBe('low');
    expect(cvssSeverity(3.9)).toBe('low');
    expect(cvssSeverity(4.0)).toBe('medium');
    expect(cvssSeverity(6.9)).toBe('medium');
    expect(cvssSeverity(7.0)).toBe('high');
    expect(cvssSeverity(8.9)).toBe('high');
    expect(cvssSeverity(9.0)).toBe('critical');
    expect(cvssSeverity(10)).toBe('critical');
  });
});

describe('enrichFinding — CWE + CVSS metadata', () => {
  it('enriches dom-xss with CWE-79 and a medium CVSS', () => {
    const r = enrichFinding({ type: 'dom-xss' });
    expect(r.cwe).toBe('CWE-79');
    expect(r.cweName).toMatch(/cross-site scripting/i);
    expect(r.cvss.vector).toMatch(/^CVSS:3\.1\//);
    expect(r.cvss.baseScore).toBe(6.1);
    expect(r.cvss.severity).toBe('medium');
  });

  it('enriches sqli-boolean and sqli-time with CWE-89 critical', () => {
    for (const t of ['sqli-boolean', 'sqli-time']) {
      const r = enrichFinding({ type: t });
      expect(r.cwe).toBe('CWE-89');
      expect(r.cvss.baseScore).toBe(9.8);
      expect(r.cvss.severity).toBe('critical');
    }
  });

  it('enriches header with CWE-693 low', () => {
    const r = enrichFinding({ type: 'header' });
    expect(r.cwe).toBe('CWE-693');
    expect(r.cvss.severity).toBe('low');
  });

  it('enriches oob with CWE-918 high', () => {
    const r = enrichFinding({ type: 'oob' });
    expect(r.cwe).toBe('CWE-918');
    expect(r.cvss.severity).toBe('high');
  });

  it('enriches a secret key with CWE-798 critical', () => {
    const r = enrichFinding({ type: 'aws_access_key' });
    expect(r.cwe).toBe('CWE-798');
    expect(r.cvss.severity).toBe('critical');
  });

  it('enriches a jwt with CWE-522 high', () => {
    const r = enrichFinding({ type: 'jwt' });
    expect(r.cwe).toBe('CWE-522');
    expect(r.cvss.severity).toBe('high');
  });

  it('enriches api-spec-exposed with CWE-200 (information exposure)', () => {
    const r = enrichFinding({ type: 'api-spec-exposed' });
    expect(r.cwe).toBe('CWE-200');
    expect(r.cvss.vector).toMatch(/^CVSS:3\.1\//);
  });

  it('enriches graphql-introspection with CWE-200 (information exposure)', () => {
    const r = enrichFinding({ type: 'graphql-introspection' });
    expect(r.cwe).toBe('CWE-200');
    expect(r.cvss.vector).toMatch(/^CVSS:3\.1\//);
  });

  it('enriches api-auth with CWE-306, api-idor-candidate with CWE-639, api-injection with CWE-74', () => {
    expect(enrichFinding({ type: 'api-auth' }).cwe).toBe('CWE-306');
    expect(enrichFinding({ type: 'api-idor-candidate' }).cwe).toBe('CWE-639');
    expect(enrichFinding({ type: 'api-injection' }).cwe).toBe('CWE-74');
  });

  it('enriches ws-cswsh with CWE-346 and ws-injection with CWE-74', () => {
    expect(enrichFinding({ type: 'ws-cswsh' }).cwe).toBe('CWE-346');
    expect(enrichFinding({ type: 'ws-injection' }).cwe).toBe('CWE-74');
  });

  it("leaves cwe/cvss null for an unknown type but doesn't throw", () => {
    const r = enrichFinding({ type: 'quantum_bug' });
    expect(r.cwe).toBeNull();
    expect(r.cvss).toBeNull();
  });

  it('is additive — never touches severity or confidence', () => {
    const r = enrichFinding({
      type: 'dom-xss',
      severity: 'high',
      confidence: 80,
    });
    expect(r.severity).toBe('high'); // source severity untouched
    expect(r.confidence).toBe(80); // gate confidence untouched
    expect(r.cwe).toBe('CWE-79'); // but enrichment was added
  });

  it('does not mutate the input finding', () => {
    const input = { type: 'sqli-boolean' };
    enrichFinding(input);
    expect(input.cwe).toBeUndefined();
    expect(input.cvss).toBeUndefined();
  });
});

describe('enrichFinding — EPSS/KEV only when a CVE is present', () => {
  it('leaves epss null and kev false when there is no cve', () => {
    const r = enrichFinding({ type: 'dom-xss', epss: 0.5, kev: true }); // no cve
    expect(r.cve).toBeNull();
    expect(r.epss).toBeNull();
    expect(r.kev).toBe(false);
  });

  it('passes epss/kev through when a cve is present', () => {
    const r = enrichFinding({
      type: 'oob',
      cve: 'CVE-2021-1234',
      epss: 0.42,
      kev: true,
    });
    expect(r.cve).toBe('CVE-2021-1234');
    expect(r.epss).toBe(0.42);
    expect(r.kev).toBe(true);
  });
});

describe('enrichFindings + CLASS_META', () => {
  it('maps a list and tolerates a non-array', () => {
    const out = enrichFindings([{ type: 'dom-xss' }, { type: 'header' }]);
    expect(out).toHaveLength(2);
    expect(out[0].cwe).toBe('CWE-79');
    expect(enrichFindings(null)).toEqual([]);
  });

  it('every CLASS_META entry has a valid CVSS vector that scores > 0', () => {
    for (const key of Object.keys(CLASS_META)) {
      expect(cvssBaseScore(CLASS_META[key].vector)).toBeGreaterThan(0);
    }
  });
});
