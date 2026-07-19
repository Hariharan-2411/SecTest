// Attack-graph substrate (A1) — pure, unit-testable (no chrome.*/network).
//
// Projects the existing flat findings + per-host inventory into one directed
// graph so chaining can become path-finding instead of re-reasoning a list.
// A1 builds the base topology (hosts, findings, endpoints, secrets + exposes /
// affected-by edges); later phases add exploit edges (leads-to / confirmed-by)
// and path-finding. Scope-gated: nothing out-of-scope enters the graph.
//
// Shapes:
//   Node = { id, type, label, data? }
//   Edge = { from, to, rel }
//   Graph = { nodes: Node[], edges: Edge[] }

import { evaluateScope } from './scope';
import { PLAYBOOKS, matchPlaybooks } from './chainPlaybooks';
import { normalizeChains, MAX_STEPS } from './chains';

export const NODE_TYPES = ['host', 'finding', 'endpoint', 'secret', 'tech'];
export const EDGE_TYPES = ['exposes', 'affected-by', 'runs', 'leads-to', 'confirmed-by'];

export function nodesOfType(graph, type) {
  return (graph && Array.isArray(graph.nodes) ? graph.nodes : []).filter((n) => n.type === type);
}

export function findNode(graph, id) {
  return (graph && Array.isArray(graph.nodes) ? graph.nodes : []).find((n) => n.id === id) || null;
}

export function outEdges(graph, id) {
  return (graph && Array.isArray(graph.edges) ? graph.edges : []).filter((e) => e.from === id);
}

const hostNodeId = (h) => `host:${h}`;

/**
 * Build the base attack graph from findings + inventory. Pure; never throws.
 * @param {{findings?:object[], inventory?:Record<string,object>, scope?:object}} input
 * @returns {{nodes:object[], edges:object[]}}
 */
export function buildGraph({ findings = [], inventory = {}, scope } = {}) {
  const nodes = [];
  const edges = [];
  const nodeIds = new Set();
  const edgeKeys = new Set();

  const addNode = (id, type, label, data) => {
    if (nodeIds.has(id)) return;
    nodeIds.add(id);
    nodes.push({ id, type, label: label || id, ...(data ? { data } : {}) });
  };
  const addEdge = (from, to, rel) => {
    const key = `${from}|${to}|${rel}`;
    if (edgeKeys.has(key)) return;
    edgeKeys.add(key);
    edges.push({ from, to, rel });
  };
  const inScope = (host) => {
    if (!scope) return true;
    const url = /^https?:\/\//i.test(host) ? host : `https://${host}`;
    return evaluateScope(url, scope).allowed;
  };

  for (const f of Array.isArray(findings) ? findings : []) {
    if (!f || !f.id) continue;
    const host = f.host || '';
    if (host && !inScope(host)) continue; // out-of-scope host → skip the finding
    const fid = `finding:${f.id}`;
    addNode(fid, 'finding', f.title || f.type || f.id, {
      type: f.type,
      severity: f.severity,
      confidence: f.confidence,
    });
    if (host) {
      addNode(hostNodeId(host), 'host', host);
      addEdge(hostNodeId(host), fid, 'affected-by');
    }
  }

  const inv = inventory && typeof inventory === 'object' ? inventory : {};
  for (const host of Object.keys(inv)) {
    if (!inScope(host)) continue;
    const data = inv[host] || {};
    addNode(hostNodeId(host), 'host', host);
    for (const ep of Array.isArray(data.endpoints) ? data.endpoints : []) {
      if (typeof ep !== 'string') continue;
      const eid = `endpoint:${ep}`;
      addNode(eid, 'endpoint', ep);
      addEdge(hostNodeId(host), eid, 'exposes');
    }
    for (const s of Array.isArray(data.secrets) ? data.secrets : []) {
      const t = s && s.type;
      if (!t) continue;
      const sid = `secret:${host}:${t}`;
      addNode(sid, 'secret', t, { type: t });
      addEdge(hostNodeId(host), sid, 'exposes');
    }
  }

  return { nodes, edges };
}

/** Add an edge to an existing graph, deduped by from|to|rel. Mutates + returns. */
export function addEdge(graph, from, to, rel, data) {
  if (!graph || !Array.isArray(graph.edges)) return graph;
  if (!graph.edges.some((e) => e.from === from && e.to === to && e.rel === rel)) {
    graph.edges.push({ from, to, rel, ...(data ? { data } : {}) });
  }
  return graph;
}

/**
 * A2 — add exploit `leads-to` edges between finding nodes, derived from playbook
 * matches. For each matched playbook, satisfied links are ordered by their
 * position in the playbook (the exploit progression), and consecutive real
 * findings are linked. Only connects finding nodes already present in the graph.
 * Pure w.r.t. inputs; mutates + returns the graph. Never throws.
 */
export function addPlaybookEdges(graph, { findings, scope } = {}) {
  if (!graph || !Array.isArray(graph.edges)) return graph;
  const pbById = new Map(PLAYBOOKS.map((p) => [p.id, p]));
  const matches = matchPlaybooks(findings, { scope });
  for (const m of matches) {
    const pb = pbById.get(m.playbookId);
    if (!pb) continue;
    const order = new Map(pb.links.map((l, i) => [l.id, i]));
    const sat = [...m.satisfied].sort(
      (a, b) => (order.get(a.linkId) ?? 0) - (order.get(b.linkId) ?? 0)
    );
    for (let i = 0; i < sat.length - 1; i++) {
      const from = `finding:${sat[i].findingId}`;
      const to = `finding:${sat[i + 1].findingId}`;
      if (findNode(graph, from) && findNode(graph, to)) {
        addEdge(graph, from, to, 'leads-to', { playbookId: m.playbookId });
      }
    }
  }
  return graph;
}

/** Convenience: base topology (A1) + exploit edges (A2) in one call. */
export function buildAttackGraph({ findings = [], inventory = {}, scope } = {}) {
  const graph = buildGraph({ findings, inventory, scope });
  addPlaybookEdges(graph, { findings, scope });
  return graph;
}

// Enumerate MAXIMAL simple `leads-to` paths (≥2 finding nodes) starting from chain
// roots (nodes with no incoming leads-to edge). Bounded by length and count.
function findChainPaths(graph, { maxLen = MAX_STEPS, maxPaths = 20 } = {}) {
  const adj = new Map();
  const targets = new Set();
  for (const e of (graph && Array.isArray(graph.edges) ? graph.edges : [])) {
    if (e.rel !== 'leads-to') continue;
    if (!adj.has(e.from)) adj.set(e.from, []);
    adj.get(e.from).push(e.to);
    targets.add(e.to);
  }
  const roots = [...adj.keys()].filter((n) => !targets.has(n));
  const paths = [];
  const dfs = (node, path, visited) => {
    if (paths.length >= maxPaths) return;
    let extended = false;
    for (const nx of adj.get(node) || []) {
      if (visited.has(nx) || path.length >= maxLen) continue;
      extended = true;
      visited.add(nx);
      path.push(nx);
      dfs(nx, path, visited);
      path.pop();
      visited.delete(nx);
      if (paths.length >= maxPaths) return;
    }
    if (!extended && path.length >= 2) paths.push([...path]);
  };
  for (const r of roots) {
    if (paths.length >= maxPaths) break;
    dfs(r, [r], new Set([r]));
  }
  return paths;
}

/**
 * A3 — propose exploit chains as path-finding over the graph's `leads-to` edges,
 * then VALIDATE each path through the same chains.normalizeChains gate as the LLM
 * path (grounded in real findings, scope re-checked, ≥2 steps). Cross-host chains
 * fall out when a path spans hosts. Deterministic; never throws.
 * @returns {{chains:object[], rejected:object[], source:'graph'}}
 */
export function proposeGraphChains(graph, { findings, scope, maxPaths = 20 } = {}) {
  const paths = findChainPaths(graph, { maxPaths });
  const rawChains = paths.map((p) => ({
    steps: p.map((nodeId) => ({ findingId: String(nodeId).replace(/^finding:/, '') })),
    rationale: 'derived from the attack graph',
  }));
  const { chains, rejected } = normalizeChains(rawChains, { findings, scope });
  return { chains, rejected, source: 'graph' };
}
