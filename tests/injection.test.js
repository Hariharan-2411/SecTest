import { describe, it, expect } from '@jest/globals';
import {
  planParamInjections,
  classifyReflection,
  planAuthReplays,
  classifyAuthReplay,
  detectIdorCandidates,
  buildInjectionFindings,
} from '../src/utils/injection';

describe('planParamInjections', () => {
  const inv = [
    { method: 'GET', path: '/api/search', params: ['q'], hasAuth: false, count: 1, example: 'https://x.com/api/search?q=hi' },
    { method: 'POST', path: '/api/users', params: ['name'], hasAuth: true, count: 1, example: 'https://x.com/api/users' },
    { method: 'GET', path: '/api/ping', params: [], hasAuth: false, count: 1, example: 'https://x.com/api/ping' },
  ];

  it('plans one payload per (param, family) for GET endpoints with params only', () => {
    const targets = planParamInjections(inv, { families: ['xss', 'sqli'] });
    // only GET /api/search has a param → 2 families = 2 targets
    expect(targets).toHaveLength(2);
    expect(targets.every((t) => t.method === 'GET')).toBe(true);
    expect(targets.every((t) => t.param === 'q')).toBe(true);
    expect(targets.map((t) => t.family).sort()).toEqual(['sqli', 'xss']);
    expect(targets.find((t) => t.family === 'xss').payload).toBeTruthy();
  });

  it('never plans against POST/PUT/DELETE (read-only testing)', () => {
    const targets = planParamInjections(inv, { families: ['xss'] });
    expect(targets.some((t) => t.path === '/api/users')).toBe(false);
  });

  it('is safe for non-arrays', () => {
    expect(planParamInjections(null, {})).toEqual([]);
  });
});

describe('classifyReflection', () => {
  it('flags a payload reflected in the injected body but not the baseline', () => {
    const r = classifyReflection({
      baselineBody: 'results for hi',
      injectedBody: 'results for <script>alert(1)</script>',
      payload: '<script>alert(1)</script>',
    });
    expect(r.reflected).toBe(true);
  });

  it('does not flag a payload already present in the baseline', () => {
    const r = classifyReflection({
      baselineBody: 'x <script>alert(1)</script>',
      injectedBody: 'x <script>alert(1)</script>',
      payload: '<script>alert(1)</script>',
    });
    expect(r.reflected).toBe(false);
  });

  it('is safe for missing bodies', () => {
    expect(classifyReflection({ payload: 'p' }).reflected).toBe(false);
  });
});

describe('planAuthReplays', () => {
  it('selects GET endpoints observed carrying auth', () => {
    const inv = [
      { method: 'GET', path: '/api/me', params: [], hasAuth: true, example: 'https://x.com/api/me' },
      { method: 'GET', path: '/api/public', params: [], hasAuth: false, example: 'https://x.com/api/public' },
      { method: 'POST', path: '/api/x', hasAuth: true, example: 'https://x.com/api/x' },
    ];
    const t = planAuthReplays(inv);
    expect(t).toHaveLength(1);
    expect(t[0].path).toBe('/api/me');
  });
});

describe('classifyAuthReplay', () => {
  it('flags a candidate when the anon reply is 2xx with similar length', () => {
    const r = classifyAuthReplay({ authed: { status: 200, length: 500 }, anon: { status: 200, length: 490 } });
    expect(r.candidate).toBe(true);
  });

  it('is not a candidate when auth is enforced (401/403)', () => {
    const r = classifyAuthReplay({ authed: { status: 200, length: 500 }, anon: { status: 401, length: 20 } });
    expect(r.candidate).toBe(false);
    expect(r.reason).toBe('enforced');
  });

  it('is not a candidate when the anon content is very different', () => {
    const r = classifyAuthReplay({ authed: { status: 200, length: 500 }, anon: { status: 200, length: 40 } });
    expect(r.candidate).toBe(false);
  });
});

describe('detectIdorCandidates', () => {
  it('flags auth-gated {id} routes only', () => {
    const inv = [
      { method: 'GET', path: '/api/users/{id}', hasAuth: true },
      { method: 'GET', path: '/api/users', hasAuth: true },
      { method: 'GET', path: '/api/items/{id}', hasAuth: false },
    ];
    const c = detectIdorCandidates(inv);
    expect(c.map((x) => x.path)).toEqual(['/api/users/{id}']);
  });
});

describe('buildInjectionFindings', () => {
  it('emits api-injection / api-auth / api-idor-candidate with the right types', () => {
    const f = buildInjectionFindings({
      host: 'x.com',
      injections: [
        { method: 'GET', path: '/api/search', param: 'q', family: 'xss', payload: '<script>alert(1)</script>', example: 'https://x.com/api/search?q=hi' },
      ],
      auth: [{ method: 'GET', path: '/api/me', example: 'https://x.com/api/me', reason: '2xx without auth' }],
      idor: [{ method: 'GET', path: '/api/users/{id}' }],
    });
    expect(f.find((x) => x.type === 'api-injection')).toBeTruthy();
    expect(f.find((x) => x.type === 'api-auth')).toBeTruthy();
    expect(f.find((x) => x.type === 'api-idor-candidate')).toBeTruthy();
    expect(f.find((x) => x.type === 'api-auth').source).toBe('api-inject');
    expect(f.find((x) => x.type === 'api-injection').evidence).toContain('q');
  });

  it('returns nothing when there are no candidates', () => {
    expect(buildInjectionFindings({ host: 'x.com', injections: [], auth: [], idor: [] })).toEqual([]);
  });
});
