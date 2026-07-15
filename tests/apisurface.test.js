import { describe, it, expect } from '@jest/globals';
import {
  templatizePath,
  parseOpenApi,
  inventoryFromRequests,
  buildApiFindings,
  mergeApiEvent,
  isApiEvent,
  apiSpecCandidates,
  mergeSpecEndpoints,
} from '../src/utils/apisurface';

describe('templatizePath', () => {
  it('collapses a numeric id segment to {id}', () => {
    expect(templatizePath('/users/123')).toBe('/users/{id}');
  });

  it('collapses every dynamic segment, keeping static ones', () => {
    expect(templatizePath('/users/123/posts/456')).toBe(
      '/users/{id}/posts/{id}'
    );
  });

  it('collapses a UUID and strips host + query, preserving version', () => {
    expect(
      templatizePath(
        'https://api.x.com/v1/orders/550e8400-e29b-41d4-a716-446655440000?x=1'
      )
    ).toBe('/v1/orders/{id}');
  });

  it('collapses a 24-char hex object id', () => {
    expect(templatizePath('/users/507f1f77bcf86cd799439011')).toBe(
      '/users/{id}'
    );
  });

  it('leaves a static path (including api version) unchanged', () => {
    expect(templatizePath('/api/v2/users')).toBe('/api/v2/users');
  });

  it('is safe for non-string / empty input', () => {
    expect(templatizePath(null)).toBe('');
    expect(templatizePath('')).toBe('');
  });
});

describe('parseOpenApi', () => {
  it('extracts method/path/params from an OpenAPI v3 spec', () => {
    const spec = {
      openapi: '3.0.0',
      paths: {
        '/users': {
          get: { parameters: [{ name: 'limit', in: 'query' }] },
          post: {},
        },
        '/users/{id}': { get: {} },
      },
    };
    const eps = parseOpenApi(spec);
    expect(eps).toEqual(
      expect.arrayContaining([
        { method: 'GET', path: '/users', params: ['limit'] },
        { method: 'POST', path: '/users', params: [] },
        { method: 'GET', path: '/users/{id}', params: [] },
      ])
    );
    expect(eps).toHaveLength(3);
  });

  it('prefixes the Swagger v2 basePath onto each path', () => {
    const spec = {
      swagger: '2.0',
      basePath: '/api/v1',
      paths: { '/ping': { get: {} } },
    };
    expect(parseOpenApi(spec)).toEqual([
      { method: 'GET', path: '/api/v1/ping', params: [] },
    ]);
  });

  it('is safe for malformed / empty input', () => {
    expect(parseOpenApi(null)).toEqual([]);
    expect(parseOpenApi({})).toEqual([]);
    expect(parseOpenApi({ paths: 'nope' })).toEqual([]);
  });
});

describe('inventoryFromRequests', () => {
  it('templatizes, de-dupes by method+path, unions params, counts, and flags auth', () => {
    const events = [
      {
        url: 'https://x.com/api/users/1?limit=10',
        method: 'GET',
        type: 'xmlhttprequest',
        requestHeaders: [{ name: 'Authorization', value: 'Bearer x' }],
      },
      {
        url: 'https://x.com/api/users/2?offset=5',
        method: 'GET',
        type: 'xmlhttprequest',
      },
      { url: 'https://x.com/index.html', method: 'GET', type: 'main_frame' },
    ];
    const inv = inventoryFromRequests(events);
    expect(inv).toHaveLength(1);
    expect(inv[0]).toMatchObject({
      method: 'GET',
      path: '/api/users/{id}',
      hasAuth: true,
      count: 2,
    });
    expect(inv[0].params.sort()).toEqual(['limit', 'offset']);
  });

  it('keeps distinct method+path pairs separate', () => {
    const events = [
      { url: 'https://x.com/api/a', method: 'GET', type: 'xmlhttprequest' },
      { url: 'https://x.com/api/a', method: 'POST', type: 'xmlhttprequest' },
    ];
    expect(inventoryFromRequests(events)).toHaveLength(2);
  });

  it('is safe for non-array input', () => {
    expect(inventoryFromRequests(null)).toEqual([]);
  });
});

describe('buildApiFindings', () => {
  it('emits an api-spec-exposed finding when a readable spec was found', () => {
    const findings = buildApiFindings({
      host: 'x.com',
      specUrl: 'https://x.com/openapi.json',
      specEndpoints: [
        { method: 'GET', path: '/users' },
        { method: 'POST', path: '/users' },
      ],
      inventory: [],
    });
    const spec = findings.find((f) => f.type === 'api-spec-exposed');
    expect(spec).toBeTruthy();
    expect(spec.host).toBe('x.com');
    expect(spec.ref).toBe('https://x.com/openapi.json');
    expect(spec.severity).toBe('low');
    // normalized shape from findings.js
    expect(spec.id).toBeTruthy();
    expect(spec.firstSeen).toBeTruthy();
    expect(spec.source).toBe('api-recon');
  });

  it('emits an informational api-surface summary when endpoints were inventoried', () => {
    const findings = buildApiFindings({
      host: 'x.com',
      inventory: [
        { method: 'GET', path: '/api/users/{id}', params: ['limit'], count: 2 },
      ],
    });
    const surface = findings.find((f) => f.type === 'api-surface');
    expect(surface).toBeTruthy();
    expect(surface.severity).toBe('informational');
    expect(surface.evidence).toContain('/api/users/{id}');
  });

  it('returns nothing when there is neither a spec nor an inventory', () => {
    expect(buildApiFindings({ host: 'x.com', inventory: [] })).toEqual([]);
  });
});

describe('isApiEvent', () => {
  it('accepts XHR/fetch and api-ish paths, rejects page/asset loads', () => {
    expect(
      isApiEvent({ url: 'https://x.com/api/x', type: 'xmlhttprequest' })
    ).toBe(true);
    expect(isApiEvent({ url: 'https://x.com/v1/api/users', type: 'other' })).toBe(
      true
    );
    expect(isApiEvent({ url: 'https://x.com/index.html', type: 'main_frame' })).toBe(
      false
    );
    expect(isApiEvent(null)).toBe(false);
  });
});

describe('mergeApiEvent', () => {
  it('folds one event into an inventory, deduping by method+path', () => {
    let inv = mergeApiEvent([], {
      url: 'https://x.com/api/users/1?limit=10',
      method: 'GET',
      type: 'xmlhttprequest',
      requestHeaders: [{ name: 'Authorization', value: 'Bearer x' }],
    });
    expect(inv).toHaveLength(1);
    expect(inv[0]).toMatchObject({
      method: 'GET',
      path: '/api/users/{id}',
      hasAuth: true,
      count: 1,
    });
    inv = mergeApiEvent(inv, {
      url: 'https://x.com/api/users/2?offset=5',
      method: 'GET',
      type: 'xmlhttprequest',
    });
    expect(inv).toHaveLength(1);
    expect(inv[0].count).toBe(2);
    expect(inv[0].params.sort()).toEqual(['limit', 'offset']);
  });

  it('returns the inventory unchanged for a non-API event', () => {
    const inv = [
      { method: 'GET', path: '/api/a', params: [], hasAuth: false, count: 1 },
    ];
    expect(
      mergeApiEvent(inv, { url: 'https://x.com/logo.png', type: 'image' })
    ).toBe(inv);
  });
});

describe('apiSpecCandidates', () => {
  it('builds well-known spec URLs from the page origin', () => {
    const urls = apiSpecCandidates('https://x.com/app/page?a=1');
    expect(urls).toContain('https://x.com/openapi.json');
    expect(urls).toContain('https://x.com/v2/api-docs');
  });
  it('is safe for a bad url', () => {
    expect(apiSpecCandidates('not a url')).toEqual([]);
  });
});

describe('mergeSpecEndpoints', () => {
  it('unions spec routes into the inventory without duplicating existing ones', () => {
    const inv = [
      { method: 'GET', path: '/users', params: [], hasAuth: false, count: 3 },
    ];
    const merged = mergeSpecEndpoints(inv, [
      { method: 'GET', path: '/users', params: ['limit'] },
      { method: 'POST', path: '/users', params: [] },
    ]);
    expect(merged).toHaveLength(2);
    // existing GET /users untouched (keeps its count)
    expect(merged.find((e) => e.method === 'GET').count).toBe(3);
    // new POST /users marked as spec-sourced
    expect(merged.find((e) => e.method === 'POST')).toMatchObject({
      fromSpec: true,
    });
  });
});
