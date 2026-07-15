import { describe, it, expect } from '@jest/globals';
import {
  introspectionQuery,
  parseSchema,
  surfaceFromSchema,
  detectSuggestions,
  isGraphqlPath,
  graphqlCandidates,
  detectBatching,
  buildGraphqlFindings,
} from '../src/utils/graphql';

describe('introspectionQuery', () => {
  it('requests __schema with its types and fields', () => {
    const q = introspectionQuery();
    expect(q).toContain('__schema');
    expect(q).toContain('queryType');
    expect(q).toContain('fields');
  });
});

describe('parseSchema', () => {
  it('parses a { data: { __schema } } introspection result', () => {
    const json = {
      data: {
        __schema: {
          queryType: { name: 'Query' },
          mutationType: { name: 'Mutation' },
          types: [{ name: 'Query', kind: 'OBJECT', fields: [{ name: 'user' }] }],
        },
      },
    };
    const s = parseSchema(json);
    expect(s.queryType.name).toBe('Query');
    expect(s.types).toHaveLength(1);
  });

  it('accepts a bare { __schema } too', () => {
    const s = parseSchema({ __schema: { queryType: { name: 'Q' }, types: [] } });
    expect(s.queryType.name).toBe('Q');
  });

  it('returns null when there is no __schema (introspection disabled)', () => {
    expect(parseSchema({ errors: [{ message: 'introspection disabled' }] })).toBeNull();
    expect(parseSchema(null)).toBeNull();
  });
});

describe('surfaceFromSchema', () => {
  const schema = {
    queryType: { name: 'Query' },
    mutationType: { name: 'Mutation' },
    types: [
      { name: 'Query', kind: 'OBJECT', fields: [{ name: 'user' }, { name: 'users' }] },
      { name: 'Mutation', kind: 'OBJECT', fields: [{ name: 'login' }] },
      { name: 'User', kind: 'OBJECT', fields: [{ name: 'id' }] },
      { name: '__Schema', kind: 'OBJECT', fields: [] },
    ],
  };

  it('enumerates queries, mutations, and non-introspection types', () => {
    const surf = surfaceFromSchema(schema);
    expect(surf.queries.sort()).toEqual(['user', 'users']);
    expect(surf.mutations).toEqual(['login']);
    expect(surf.types).toContain('User');
    expect(surf.types).not.toContain('__Schema');
  });

  it('is safe for null/empty', () => {
    expect(surfaceFromSchema(null)).toEqual({ queries: [], mutations: [], types: [] });
  });
});

describe('detectSuggestions', () => {
  it('extracts a field name from a "Did you mean" error', () => {
    const json = {
      errors: [
        { message: 'Cannot query field "usr" on type "Query". Did you mean "user"?' },
      ],
    };
    expect(detectSuggestions(json)).toEqual(['user']);
  });

  it('handles multiple suggestions', () => {
    const json = { errors: [{ message: 'Did you mean "user" or "users"?' }] };
    expect(detectSuggestions(json).sort()).toEqual(['user', 'users']);
  });

  it('returns [] when there are no suggestions', () => {
    expect(detectSuggestions({ errors: [{ message: 'syntax error' }] })).toEqual([]);
    expect(detectSuggestions(null)).toEqual([]);
  });
});

describe('isGraphqlPath', () => {
  it('detects common graphql endpoint paths', () => {
    expect(isGraphqlPath('https://x.com/graphql')).toBe(true);
    expect(isGraphqlPath('/api/graphql')).toBe(true);
    expect(isGraphqlPath('/v1/gql')).toBe(true);
    expect(isGraphqlPath('/users')).toBe(false);
  });
});

describe('graphqlCandidates', () => {
  it('builds candidate graphql endpoints from the page origin', () => {
    const c = graphqlCandidates('https://x.com/app');
    expect(c).toContain('https://x.com/graphql');
    expect(c).toContain('https://x.com/api/graphql');
  });
  it('is safe for a bad url', () => {
    expect(graphqlCandidates('nope')).toEqual([]);
  });
});

describe('detectBatching', () => {
  it('flags an array response as batching-enabled', () => {
    expect(detectBatching([{ data: {} }, { data: {} }])).toBe(true);
    expect(detectBatching({ data: {} })).toBe(false);
    expect(detectBatching(null)).toBe(false);
  });
});

describe('buildGraphqlFindings', () => {
  it('emits a graphql-introspection finding when introspection is enabled', () => {
    const f = buildGraphqlFindings({
      host: 'x.com',
      endpoint: 'https://x.com/graphql',
      introspection: true,
      surface: { queries: ['user'], mutations: ['login'], types: ['User'] },
    });
    const intro = f.find((x) => x.type === 'graphql-introspection');
    expect(intro).toBeTruthy();
    expect(intro.severity).toBe('low');
    expect(intro.ref).toBe('https://x.com/graphql');
    expect(intro.source).toBe('graphql-recon');
  });

  it('emits graphql-suggestions when field suggestions leaked', () => {
    const f = buildGraphqlFindings({
      host: 'x.com',
      endpoint: 'e',
      introspection: false,
      suggestions: ['user', 'users'],
    });
    const s = f.find((x) => x.type === 'graphql-suggestions');
    expect(s).toBeTruthy();
    expect(s.evidence).toContain('user');
  });

  it('emits graphql-batching when batching is accepted', () => {
    const f = buildGraphqlFindings({ host: 'x.com', endpoint: 'e', batching: true });
    expect(f.find((x) => x.type === 'graphql-batching')).toBeTruthy();
  });

  it('returns nothing when the endpoint is locked down', () => {
    expect(
      buildGraphqlFindings({ host: 'x.com', endpoint: 'e', introspection: false })
    ).toEqual([]);
  });
});
