import { describe, it, expect } from '@jest/globals';
import {
  assembleContext,
  pickRelevantEndpoints,
  paramHint,
} from '../src/utils/escalationContext';

describe('paramHint', () => {
  it('uses an explicit param field', () => {
    expect(paramHint({ param: 'id' })).toBe('id');
  });
  it('recovers a quoted param from the title', () => {
    expect(paramHint({ title: 'Boolean-based injection candidate on "userId"' })).toBe('userId');
  });
  it('returns empty when none is evident', () => {
    expect(paramHint({ title: 'Missing CSP' })).toBe('');
  });
});

describe('pickRelevantEndpoints', () => {
  it('ranks param matches first, then query strings, then the rest', () => {
    const eps = ['/static/app.js', '/search?q=1', '/item?id=5', '/home'];
    const out = pickRelevantEndpoints(eps, 'id');
    expect(out[0]).toBe('/item?id=5'); // param match
    expect(out[1]).toBe('/search?q=1'); // has query
    expect(out.slice(-2)).toEqual(['/static/app.js', '/home']); // stable rest
  });
  it('with no param, prefers query-string endpoints', () => {
    const out = pickRelevantEndpoints(['/a', '/b?x=1'], '');
    expect(out[0]).toBe('/b?x=1');
  });
  it('handles non-array input', () => {
    expect(pickRelevantEndpoints(null, 'id')).toEqual([]);
  });
});

describe('assembleContext', () => {
  const inventory = {
    endpoints: Array.from({ length: 50 }, (_, i) => `/api/${i}?id=${i}`),
    params: Array.from({ length: 50 }, (_, i) => `p${i}`),
    forms: [{ method: 'post', action: '/login', fieldCount: 2 }],
    secrets: [{ type: 'aws_access_key', preview: 'AKIA…MPLE' }],
    cookieNames: ['sid'],
  };
  const findings = [
    { id: 'f1', type: 'sqli-boolean', severity: 'high', title: 'on "id"' },
    { id: 'f2', type: 'header', severity: 'low', title: 'Missing CSP' },
  ];

  it('bounds every list', () => {
    const c = assembleContext(findings[0], { inventory, findings, host: 'x.com' });
    expect(c.inventory.endpoints.length).toBeLessThanOrEqual(30);
    expect(c.inventory.params.length).toBeLessThanOrEqual(30);
    expect(c.relatedFindings.length).toBeLessThanOrEqual(10);
  });

  it('excludes the finding itself from relatedFindings', () => {
    const c = assembleContext(findings[0], { inventory, findings });
    // f1 is the finding being escalated → excluded; only f2 remains.
    expect(c.relatedFindings).toHaveLength(1);
    expect(c.relatedFindings[0].type).toBe('header');
  });

  it('sends secret TYPE only — never the value/preview', () => {
    const c = assembleContext(findings[0], { inventory });
    expect(c.inventory.secrets).toEqual([{ type: 'aws_access_key' }]);
    expect(JSON.stringify(c)).not.toContain('AKIA');
  });

  it('trims long evidence', () => {
    const long = 'x'.repeat(2000);
    const c = assembleContext({ type: 'x', evidence: long });
    expect(c.finding.evidence.length).toBeLessThanOrEqual(500);
  });

  it('includes recon frameworks when provided', () => {
    const c = assembleContext(findings[0], { recon: { title: 'Home', frameworks: ['React'] } });
    expect(c.recon.frameworks).toContain('React');
  });

  it('works with empty sources', () => {
    const c = assembleContext({ type: 'header', title: 'x' });
    expect(c.inventory.endpoints).toEqual([]);
    expect(c.relatedFindings).toEqual([]);
  });
});

describe('assembleContext — chainGoals passthrough', () => {
  const goals = [
    {
      playbookId: 'xss-secret-ato',
      name: 'DOM-XSS → exposed token → account takeover',
      have: ['dom-xss'],
      missing: [{ linkId: 'token', label: 'Exposed token/secret', types: ['jwt'], hint: { verbs: ['deep_js'], note: 'scan JS' } }],
    },
  ];

  it('includes chainGoals when a non-empty array is provided', () => {
    const c = assembleContext({ type: 'dom-xss', title: 'XSS' }, { chainGoals: goals });
    expect(c.chainGoals).toEqual(goals);
  });

  it('places chainGoals before inventory so it survives the prompt clamp', () => {
    const c = assembleContext({ type: 'dom-xss', title: 'XSS' }, { chainGoals: goals });
    const keys = Object.keys(c);
    expect(keys.indexOf('chainGoals')).toBeGreaterThanOrEqual(0);
    expect(keys.indexOf('chainGoals')).toBeLessThan(keys.indexOf('inventory'));
  });

  it('omits chainGoals when absent or empty', () => {
    expect('chainGoals' in assembleContext({ type: 'dom-xss' }, {})).toBe(false);
    expect('chainGoals' in assembleContext({ type: 'dom-xss' }, { chainGoals: [] })).toBe(false);
  });
});
