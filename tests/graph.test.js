import { describe, it, expect } from '@jest/globals';
import { buildGraph, nodesOfType, findNode, outEdges, addPlaybookEdges, buildAttackGraph, proposeGraphChains } from '../src/utils/graph';

const scope = { inScope: ['*.example.com', 'example.com'], outOfScope: [] };

const findings = [
  { id: 'f1', host: 'app.example.com', type: 'dom-xss', severity: 'medium', confidence: 60, title: 'XSS' },
  { id: 'f2', host: 'evil.test', type: 'jwt', severity: 'high', title: 'leak' },
];
const inventory = {
  'app.example.com': {
    endpoints: ['https://app.example.com/api/x'],
    secrets: [{ type: 'jwt', preview: 'ey…' }],
  },
  'evil.test': { endpoints: ['https://evil.test/y'] },
};

describe('buildGraph', () => {
  it('projects an in-scope finding into a host node, finding node, and affected-by edge', () => {
    const g = buildGraph({ findings, inventory, scope });
    expect(findNode(g, 'host:app.example.com')).toBeTruthy();
    const fn = findNode(g, 'finding:f1');
    expect(fn).toBeTruthy();
    expect(fn.data.type).toBe('dom-xss');
    expect(outEdges(g, 'host:app.example.com').some((e) => e.to === 'finding:f1' && e.rel === 'affected-by')).toBe(true);
  });

  it('projects inventory endpoints and secrets as nodes with exposes edges', () => {
    const g = buildGraph({ findings, inventory, scope });
    expect(findNode(g, 'endpoint:https://app.example.com/api/x')).toBeTruthy();
    expect(findNode(g, 'secret:app.example.com:jwt')).toBeTruthy();
    const out = outEdges(g, 'host:app.example.com');
    expect(out.some((e) => e.to === 'endpoint:https://app.example.com/api/x' && e.rel === 'exposes')).toBe(true);
    expect(out.some((e) => e.to === 'secret:app.example.com:jwt' && e.rel === 'exposes')).toBe(true);
  });

  it('excludes an out-of-scope host and everything under it', () => {
    const g = buildGraph({ findings, inventory, scope });
    expect(findNode(g, 'host:evil.test')).toBeFalsy();
    expect(findNode(g, 'finding:f2')).toBeFalsy();
    expect(findNode(g, 'endpoint:https://evil.test/y')).toBeFalsy();
    expect(nodesOfType(g, 'finding').map((n) => n.id)).toEqual(['finding:f1']);
  });

  it('dedupes repeated nodes and edges', () => {
    const g = buildGraph({
      findings: [findings[0], findings[0]],
      inventory: { 'app.example.com': { endpoints: ['https://app.example.com/api/x', 'https://app.example.com/api/x'] } },
      scope,
    });
    expect(nodesOfType(g, 'finding')).toHaveLength(1);
    expect(nodesOfType(g, 'endpoint')).toHaveLength(1);
    expect(outEdges(g, 'host:app.example.com').filter((e) => e.rel === 'exposes')).toHaveLength(1);
  });

  it('includes a finding with no host as a node without a host edge', () => {
    const g = buildGraph({ findings: [{ id: 'x', type: 'nuclei', title: 'n' }], scope });
    expect(findNode(g, 'finding:x')).toBeTruthy();
    expect(nodesOfType(g, 'host')).toEqual([]);
  });

  it('returns an empty graph and never throws on garbage input', () => {
    expect(buildGraph()).toEqual({ nodes: [], edges: [] });
    expect(() => buildGraph({ findings: null, inventory: 5, scope })).not.toThrow();
  });
});

describe('addPlaybookEdges (A2)', () => {
  const s = { inScope: ['*.example.com'], outOfScope: [] };
  const gi = { id: 'gi', host: 'app.example.com', type: 'graphql-introspection', severity: 'medium', confidence: 60, title: 'introspection' };
  const gs = { id: 'gs', host: 'app.example.com', type: 'graphql-surface', severity: 'low', confidence: 50, title: 'surface' };

  it('adds a leads-to edge between consecutive satisfied playbook links, in link order', () => {
    const g = buildGraph({ findings: [gi, gs], scope: s });
    addPlaybookEdges(g, { findings: [gi, gs], scope: s });
    const e = g.edges.find((x) => x.rel === 'leads-to');
    expect(e).toBeTruthy();
    expect(e.from).toBe('finding:gi'); // introspection link precedes surface link
    expect(e.to).toBe('finding:gs');
    expect(e.data.playbookId).toBe('graphql-introspection-idor');
  });

  it('adds no leads-to edge when only one link is satisfied', () => {
    const g = buildGraph({ findings: [gi], scope: s });
    addPlaybookEdges(g, { findings: [gi], scope: s });
    expect(g.edges.some((x) => x.rel === 'leads-to')).toBe(false);
  });

  it('buildAttackGraph composes base topology + exploit edges', () => {
    const g = buildAttackGraph({ findings: [gi, gs], scope: s });
    expect(findNode(g, 'finding:gi')).toBeTruthy();
    expect(g.edges.some((x) => x.rel === 'leads-to')).toBe(true);
  });

  it('is idempotent — re-adding does not duplicate leads-to edges', () => {
    const g = buildGraph({ findings: [gi, gs], scope: s });
    addPlaybookEdges(g, { findings: [gi, gs], scope: s });
    addPlaybookEdges(g, { findings: [gi, gs], scope: s });
    expect(g.edges.filter((x) => x.rel === 'leads-to')).toHaveLength(1);
  });
});

describe('proposeGraphChains (A3)', () => {
  const s = { inScope: ['*.example.com'], outOfScope: [] };
  const gi = { id: 'gi', host: 'app.example.com', type: 'graphql-introspection', severity: 'medium', confidence: 60, title: 'introspection' };
  const gs = { id: 'gs', host: 'app.example.com', type: 'graphql-surface', severity: 'low', confidence: 50, title: 'surface' };

  it('turns a leads-to path into a validated chain', () => {
    const g = buildAttackGraph({ findings: [gi, gs], scope: s });
    const r = proposeGraphChains(g, { findings: [gi, gs], scope: s });
    expect(r.source).toBe('graph');
    expect(r.chains.length).toBeGreaterThanOrEqual(1);
    const ids = r.chains[0].findingIds;
    expect(ids).toContain('gi');
    expect(ids).toContain('gs');
  });

  it('produces a cross-host chain when links live on different in-scope hosts', () => {
    const giA = { ...gi, host: 'a.example.com' };
    const gsB = { ...gs, host: 'b.example.com' };
    const g = buildAttackGraph({ findings: [giA, gsB], scope: s });
    const r = proposeGraphChains(g, { findings: [giA, gsB], scope: s });
    expect(r.chains.length).toBeGreaterThanOrEqual(1);
    expect(r.chains[0].findingIds.sort()).toEqual(['gi', 'gs']);
  });

  it('returns no chains and never throws on an edgeless or null graph', () => {
    const g = buildGraph({ findings: [gi], scope: s });
    expect(proposeGraphChains(g, { findings: [gi], scope: s }).chains).toEqual([]);
    expect(() => proposeGraphChains(null, {})).not.toThrow();
  });
});
