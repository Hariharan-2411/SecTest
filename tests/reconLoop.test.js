import { describe, it, expect, jest } from '@jest/globals';
import {
  buildReconPrompt,
  planReconStep,
  runReconLoop,
  MAX_RECON_DEPTH,
} from '../src/utils/reconLoop';

// Mock the AI provider so the default chat path is deterministic + offline.
jest.mock('../src/utils/aiProvider', () => ({
  chat: jest.fn(() => Promise.reject(new Error('no provider in tests'))),
}));

const scope = { inScope: ['*.example.com', 'example.com'], outOfScope: [] };

const subfinderBody = {
  ok: true,
  tool: 'subfinder',
  kind: 'subdomains',
  host: 'example.com',
  items: ['a.example.com', 'b.example.com'],
  count: 2,
};
const nucleiBody = {
  ok: true,
  tool: 'nuclei',
  kind: 'findings',
  host: 'app.example.com',
  items: [
    {
      templateId: 'CVE-1',
      name: 'RCE',
      severity: 'critical',
      matched: 'https://app.example.com/x',
    },
    {
      templateId: 'tls',
      name: 'TLS 1.0',
      severity: 'info',
      matched: 'app.example.com:443',
    },
  ],
  count: 2,
};

// A chat that replays a scripted list of plan objects (as JSON), one per call.
function scriptedChat(replies) {
  let i = 0;
  return jest.fn(async () =>
    JSON.stringify(replies[Math.min(i++, replies.length - 1)])
  );
}

const baseCtx = () => ({
  scope,
  budget: 20,
  budgetUsed: 0,
  executed: [],
  surface: { subdomains: [], urls: [], hosts: [], ports: [] },
  findings: [],
});

describe('buildReconPrompt — grounded, JSON-only', () => {
  it('references scope targets, the tool list, and asks for JSON', () => {
    const { messages } = buildReconPrompt(baseCtx());
    expect(messages).toHaveLength(1);
    const c = messages[0].content;
    expect(c).toContain('example.com'); // in-scope target
    expect(c).toContain('subfinder'); // a tool name
    expect(c).toMatch(/json/i);
  });
});

describe('planReconStep — parse the LLM plan (DI chat)', () => {
  it('parses a JSON plan', async () => {
    const chat = async () =>
      JSON.stringify({
        steps: [{ tool: 'httpx', target: 'app.example.com' }],
        done: false,
      });
    const p = await planReconStep(baseCtx(), { chat });
    expect(p.steps).toHaveLength(1);
    expect(p.done).toBe(false);
  });

  it('terminates safely (done:true, no steps) on a throw or non-JSON reply', async () => {
    expect(
      await planReconStep(baseCtx(), {
        chat: async () => {
          throw new Error('x');
        },
      })
    ).toEqual({ steps: [], done: true });
    expect(
      (await planReconStep(baseCtx(), { chat: async () => 'not json' })).done
    ).toBe(true);
  });
});

describe('runReconLoop — the bounded agent loop (all DI)', () => {
  it('runs safe steps, gathers findings, and returns a ranked triage', async () => {
    const chat = scriptedChat([
      {
        steps: [{ tool: 'subfinder', target: 'app.example.com' }],
        done: false,
      },
      { steps: [{ tool: 'nuclei', target: 'app.example.com' }], done: false },
      { steps: [], done: true },
    ]);
    const agentClient = {
      scan: async ({ tool }) => ({
        status: 200,
        body: tool === 'nuclei' ? nucleiBody : subfinderBody,
      }),
    };
    const approve = async () => true; // approve the active tool
    const r = await runReconLoop({
      scope,
      chat,
      agentClient,
      approve,
      budget: 10,
      maxDepth: 5,
    });
    expect(r.findings).toHaveLength(2); // from nuclei
    expect(r.triage[0].rank).toBe(1);
    expect(r.surface.subdomains).toHaveLength(2);
    expect(r.budgetUsed).toBe(2);
  });

  it('gates active tools on the approve hook — denial skips the run', async () => {
    const chat = scriptedChat([
      { steps: [{ tool: 'nuclei', target: 'app.example.com' }], done: false },
      { steps: [], done: true },
    ]);
    const agentClient = {
      scan: jest.fn(async () => ({ status: 200, body: nucleiBody })),
    };
    const r = await runReconLoop({
      scope,
      chat,
      agentClient,
      approve: async () => false,
      budget: 10,
      maxDepth: 3,
    });
    expect(r.findings).toEqual([]);
    expect(r.budgetUsed).toBe(0);
    expect(agentClient.scan).not.toHaveBeenCalled();
    expect(
      r.executed.some((e) => e.decision === 'needs_approval' && e.ran === false)
    ).toBe(true);
  });

  it('honors the per-run budget', async () => {
    const chat = scriptedChat([
      {
        steps: [
          { tool: 'subfinder', target: 'a.example.com' },
          { tool: 'httpx', target: 'b.example.com' },
        ],
        done: false,
      },
      { steps: [], done: true },
    ]);
    const agentClient = {
      scan: jest.fn(async () => ({ status: 200, body: subfinderBody })),
    };
    const r = await runReconLoop({
      scope,
      chat,
      agentClient,
      budget: 1,
      maxDepth: 3,
    });
    expect(r.budgetUsed).toBe(1);
    expect(agentClient.scan).toHaveBeenCalledTimes(1);
  });

  it('does not re-run the same tool+target twice', async () => {
    const chat = scriptedChat([
      {
        steps: [{ tool: 'subfinder', target: 'app.example.com' }],
        done: false,
      },
      {
        steps: [{ tool: 'subfinder', target: 'app.example.com' }],
        done: false,
      }, // duplicate
      { steps: [], done: true },
    ]);
    const agentClient = {
      scan: jest.fn(async () => ({ status: 200, body: subfinderBody })),
    };
    await runReconLoop({ scope, chat, agentClient, budget: 10, maxDepth: 5 });
    expect(agentClient.scan).toHaveBeenCalledTimes(1);
  });

  it('never throws when the LLM call rejects — returns an empty triage', async () => {
    const chat = async () => {
      throw new Error('boom');
    };
    const r = await runReconLoop({
      scope,
      chat,
      agentClient: { scan: async () => ({ status: 200, body: {} }) },
      budget: 5,
      maxDepth: 3,
    });
    expect(r.findings).toEqual([]);
    expect(r.triage).toEqual([]);
  });

  it('exposes a sane default depth cap', () => {
    expect(MAX_RECON_DEPTH).toBeGreaterThan(0);
  });
});
