// GraphQL surface discovery — pure, unit-testable helpers (no chrome.*/network).
//
// A GraphQL endpoint is one URL hiding a whole API. Three safe signals map it:
//   - introspection: if {__schema} answers, the entire schema (and thus the
//     query/mutation/type surface) is readable — and that itself is a finding.
//   - field suggestions: even with introspection OFF, a typo'd field can leak
//     real names via "Did you mean ...", so the schema partly leaks anyway.
//   - batching/aliasing: an array-of-queries that the server honors is a
//     rate-limit / DoS surface (reported as a candidate — never exercised).
// buildGraphqlFindings() shapes these into the normalized Finding model so they
// flow through validate -> enrich -> report like every other source.
//
// Analytical only: it parses responses the caller already collected; the actual
// (benign, read-only) introspection request is issued by the gated background
// probe, not here.

import { normalizeFinding } from './findings';

// A compact introspection query: enough to enumerate the query/mutation roots
// and every type's fields, without the full canonical (huge) introspection doc.
const INTROSPECTION_QUERY = `query IrisIntrospect {
  __schema {
    queryType { name }
    mutationType { name }
    types { name kind fields { name } }
  }
}`;

/** The introspection query string the probe POSTs. */
export function introspectionQuery() {
  return INTROSPECTION_QUERY;
}

/**
 * Normalize an introspection response into a schema object, or null when the
 * endpoint did not return a schema (introspection disabled / error / garbage).
 * Accepts both `{ data: { __schema } }` and a bare `{ __schema }`. Pure.
 */
export function parseSchema(json) {
  if (!json || typeof json !== 'object') return null;
  const schema =
    (json.data && json.data.__schema) || json.__schema || null;
  if (!schema || typeof schema !== 'object') return null;
  return {
    queryType: schema.queryType || null,
    mutationType: schema.mutationType || null,
    types: Array.isArray(schema.types) ? schema.types : [],
  };
}

/** Fields of the named root type in a schema's type list. */
function rootFields(schema, rootName) {
  if (!rootName) return [];
  const t = schema.types.find((x) => x && x.name === rootName);
  if (!t || !Array.isArray(t.fields)) return [];
  return t.fields.map((f) => f && f.name).filter((n) => typeof n === 'string' && n);
}

/**
 * Enumerate the attack surface from a parsed schema:
 * { queries, mutations, types } — root query/mutation field names plus every
 * non-introspection type name. Null/empty yields empty lists. Pure.
 */
export function surfaceFromSchema(schema) {
  if (!schema || typeof schema !== 'object' || !Array.isArray(schema.types)) {
    return { queries: [], mutations: [], types: [] };
  }
  return {
    queries: rootFields(schema, schema.queryType && schema.queryType.name),
    mutations: rootFields(schema, schema.mutationType && schema.mutationType.name),
    types: schema.types
      .map((t) => t && t.name)
      .filter((n) => typeof n === 'string' && n && !n.startsWith('__')),
  };
}

/**
 * Extract field names leaked by "Did you mean ..." errors in a GraphQL error
 * response — schema leakage even when introspection is disabled. Pure.
 */
export function detectSuggestions(json) {
  const errs = json && Array.isArray(json.errors) ? json.errors : [];
  const out = new Set();
  for (const e of errs) {
    const msg = e && typeof e.message === 'string' ? e.message : '';
    const i = msg.toLowerCase().indexOf('did you mean');
    if (i === -1) continue;
    const tail = msg.slice(i);
    const re = /["'`]([A-Za-z_][A-Za-z0-9_]*)["'`]/g;
    let m;
    while ((m = re.exec(tail))) out.add(m[1]);
  }
  return Array.from(out);
}

/** True if a URL/path looks like a GraphQL endpoint. Pure. */
export function isGraphqlPath(u) {
  if (typeof u !== 'string' || !u) return false;
  let path = u;
  try {
    path = new URL(u).pathname;
  } catch (_) {
    const q = u.indexOf('?');
    if (q >= 0) path = u.slice(0, q);
  }
  return /(^|\/)(graphql|gql)(\/|$)/i.test(path);
}

// Well-known paths where a GraphQL endpoint commonly lives.
const GQL_PATHS = [
  '/graphql',
  '/api/graphql',
  '/graphql/v1',
  '/v1/graphql',
  '/gql',
  '/api/gql',
  '/query',
];

/** Absolute candidate GraphQL endpoints for a page's origin. [] for a bad url. Pure. */
export function graphqlCandidates(pageUrl) {
  let origin;
  try {
    origin = new URL(pageUrl).origin;
  } catch (_) {
    return [];
  }
  return GQL_PATHS.map((p) => origin + p);
}

/** True if a response to a batched query is itself an array (batching honored). Pure. */
export function detectBatching(json) {
  return Array.isArray(json) && json.length > 1;
}

/**
 * Shape discovered GraphQL surface into normalized Findings:
 *   - graphql-introspection (low)          introspection is enabled
 *   - graphql-surface (informational)      the enumerated query/mutation/type surface
 *   - graphql-suggestions (informational)  field names leaked via "Did you mean"
 *   - graphql-batching (low)               query batching accepted (DoS candidate)
 * Emits nothing for a locked-down endpoint. Pure.
 */
export function buildGraphqlFindings(
  { host = '', endpoint = '', introspection = false, surface, suggestions = [], batching = false } = {},
  now = new Date().toISOString()
) {
  const out = [];
  const s = surface || { queries: [], mutations: [], types: [] };

  if (introspection) {
    out.push(
      normalizeFinding(
        {
          host,
          type: 'graphql-introspection',
          severity: 'low',
          title: 'GraphQL introspection enabled',
          evidence: `Introspection is readable at ${endpoint} — ${s.queries.length} queries, ${s.mutations.length} mutations, ${s.types.length} types exposed.`,
          source: 'graphql-recon',
          ref: endpoint,
        },
        now
      )
    );
    if (s.queries.length || s.mutations.length || s.types.length) {
      out.push(
        normalizeFinding(
          {
            host,
            type: 'graphql-surface',
            severity: 'informational',
            title: `GraphQL surface: ${s.queries.length} queries, ${s.mutations.length} mutations`,
            evidence: `queries: ${s.queries.slice(0, 40).join(', ')}\nmutations: ${s.mutations.slice(0, 40).join(', ')}`,
            source: 'graphql-recon',
            ref: endpoint,
          },
          now
        )
      );
    }
  }

  if (Array.isArray(suggestions) && suggestions.length) {
    out.push(
      normalizeFinding(
        {
          host,
          type: 'graphql-suggestions',
          severity: 'informational',
          title: 'GraphQL field suggestions leak schema',
          evidence: `Endpoint suggests real field names despite introspection controls: ${suggestions.join(', ')}.`,
          source: 'graphql-recon',
          ref: endpoint,
        },
        now
      )
    );
  }

  if (batching) {
    out.push(
      normalizeFinding(
        {
          host,
          type: 'graphql-batching',
          severity: 'low',
          title: 'GraphQL query batching enabled',
          evidence: `Endpoint honors batched/aliased queries — a rate-limit-bypass / DoS surface (candidate; not exercised).`,
          source: 'graphql-recon',
          ref: endpoint,
        },
        now
      )
    );
  }

  return out;
}
