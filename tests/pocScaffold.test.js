import { describe, it, expect } from '@jest/globals';
import { buildPocScaffold, formatPocSteps, formatPocMarkdown } from '../src/utils/pocScaffold';

describe('buildPocScaffold', () => {
  it('builds type-aware repro steps + a curl for an API injection finding', () => {
    const s = buildPocScaffold({ type: 'api-injection', host: 'app.example.com', path: '/api/search', param: 'q', title: 'Reflected injection', evidence: 'payload reflected' });
    expect(s.steps[0]).toMatch(/q/);
    expect(s.steps[0]).toMatch(/GET/i);
    expect(s.repro).toMatch(/curl/);
    expect(s.repro).toMatch(/q=/);
  });

  it('describes the source→sink flow for DOM-XSS', () => {
    const s = buildPocScaffold({ type: 'dom-xss', host: 'app.example.com', sink: 'innerHTML', sources: ['location.hash'], title: 'DOM XSS' });
    expect(s.steps.join(' ')).toMatch(/location\.hash/);
    expect(s.steps.join(' ')).toMatch(/innerHTML/);
  });

  it('says "without credentials" for a missing-auth finding', () => {
    const s = buildPocScaffold({ type: 'api-auth', host: 'app.example.com', path: '/api/me' });
    expect(s.steps.join(' ')).toMatch(/without credentials/i);
  });

  it('falls back to a generic step for an unknown type and caps evidence', () => {
    const long = 'x'.repeat(2000);
    const s = buildPocScaffold({ type: 'weird-thing', host: 'app.example.com', evidence: long });
    expect(s.steps.length).toBeGreaterThanOrEqual(1);
    expect(s.evidence.length).toBeLessThanOrEqual(500);
    expect(s.minimalDataNote).toMatch(/never exfiltrate/i);
  });

  it('never throws on garbage', () => {
    expect(() => buildPocScaffold(null)).not.toThrow();
    expect(buildPocScaffold(null).steps.length).toBeGreaterThanOrEqual(1);
  });
});

describe('formatPocSteps / formatPocMarkdown', () => {
  it('formats numbered steps + repro for the report draft', () => {
    const s = buildPocScaffold({ type: 'api-auth', host: 'app.example.com', path: '/api/me' });
    const steps = formatPocSteps(s);
    expect(steps).toMatch(/^1\. /m);
    expect(steps).toMatch(/Repro:/);
  });

  it('formats a markdown block including the minimal-data note', () => {
    const md = formatPocMarkdown(buildPocScaffold({ type: 'api-injection', host: 'x.example.com', param: 'id', evidence: 'e' }));
    expect(md).toMatch(/### PoC/);
    expect(md).toMatch(/Steps to reproduce/);
    expect(md).toMatch(/never exfiltrate/i);
  });

  it('never throws on garbage', () => {
    expect(() => formatPocSteps(null)).not.toThrow();
    expect(() => formatPocMarkdown(null)).not.toThrow();
  });
});
