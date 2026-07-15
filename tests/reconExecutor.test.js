import { describe, it, expect, jest } from '@jest/globals';
import {
  mapNucleiSeverity,
  toFindings,
  executeReconTool,
  makeAgentClient,
} from '../src/utils/reconExecutor';

const nucleiBody = {
  ok: true,
  tool: 'nuclei',
  kind: 'findings',
  host: 'app.example.com',
  items: [
    {
      templateId: 'CVE-2021-1234',
      name: 'Example RCE',
      severity: 'critical',
      matched: 'https://app.example.com/x',
    },
    {
      templateId: 'tls-version',
      name: 'TLS 1.0',
      severity: 'info',
      matched: 'app.example.com:443',
    },
  ],
  count: 2,
};

const subfinderBody = {
  ok: true,
  tool: 'subfinder',
  kind: 'subdomains',
  host: 'example.com',
  items: ['a.example.com', 'b.example.com'],
  count: 2,
};

describe('mapNucleiSeverity', () => {
  it('maps nuclei severities onto the finding severity set', () => {
    expect(mapNucleiSeverity('info')).toBe('informational');
    expect(mapNucleiSeverity('critical')).toBe('critical');
    expect(mapNucleiSeverity('HIGH')).toBe('high');
    expect(mapNucleiSeverity('weird')).toBe('medium');
    expect(mapNucleiSeverity(undefined)).toBe('medium');
  });
});

describe('toFindings — normalize a /scan body', () => {
  it('turns nuclei items into findings', () => {
    const f = toFindings(nucleiBody);
    expect(f).toHaveLength(2);
    expect(f[0].type).toBe('nuclei');
    expect(f[0].severity).toBe('critical');
    expect(f[0].title).toBe('Example RCE');
    expect(f[0].ref).toBe('CVE-2021-1234');
    expect(f[0].host).toBe('app.example.com');
    expect(f[1].severity).toBe('informational');
  });

  it('returns no findings for a recon-surface body (subdomains/urls/ports)', () => {
    expect(toFindings(subfinderBody)).toEqual([]);
    expect(toFindings({ kind: 'urls', items: ['x'] })).toEqual([]);
    expect(toFindings({})).toEqual([]);
  });
});

describe('executeReconTool — DI, never throws', () => {
  const call = {
    tool: 'nuclei',
    target: 'app.example.com',
    profile: 'quick',
    risk: 'active',
  };

  it('returns findings on a successful nuclei scan', async () => {
    const agentClient = {
      scan: jest.fn(async () => ({ status: 200, body: nucleiBody })),
    };
    const r = await executeReconTool(call, { agentClient });
    expect(r.ok).toBe(true);
    expect(r.kind).toBe('findings');
    expect(r.findings).toHaveLength(2);
    expect(agentClient.scan).toHaveBeenCalledWith({
      tool: 'nuclei',
      target: 'app.example.com',
      profile: 'quick',
    });
  });

  it('returns recon surface (no findings) for a safe tool', async () => {
    const agentClient = {
      scan: async () => ({ status: 200, body: subfinderBody }),
    };
    const r = await executeReconTool(
      { tool: 'subfinder', target: 'example.com' },
      { agentClient }
    );
    expect(r.ok).toBe(true);
    expect(r.findings).toEqual([]);
    expect(r.items).toHaveLength(2);
    expect(r.kind).toBe('subdomains');
  });

  it('surfaces an out-of-scope 403 as an error result', async () => {
    const agentClient = {
      scan: async () => ({
        status: 403,
        body: { error: 'out_of_scope', host: 'evil.com' },
      }),
    };
    const r = await executeReconTool(call, { agentClient });
    expect(r.ok).toBe(false);
    expect(r.error).toBe('out_of_scope');
    expect(r.findings).toEqual([]);
  });

  it('maps 501/429 to their error codes', async () => {
    const notInstalled = {
      scan: async () => ({
        status: 501,
        body: { error: 'tool_not_installed', tool: 'nuclei' },
      }),
    };
    expect(
      (await executeReconTool(call, { agentClient: notInstalled })).error
    ).toBe('tool_not_installed');
    const limited = {
      scan: async () => ({ status: 429, body: { error: 'rate_limited' } }),
    };
    expect((await executeReconTool(call, { agentClient: limited })).error).toBe(
      'rate_limited'
    );
  });

  it('never throws when the agent call rejects', async () => {
    const agentClient = {
      scan: async () => {
        throw new Error('ECONNREFUSED');
      },
    };
    const r = await executeReconTool(call, { agentClient });
    expect(r.ok).toBe(false);
    expect(r.error).toBe('call_failed');
  });

  it('fails safely when no agent client is provided', async () => {
    const r = await executeReconTool(call, {});
    expect(r.ok).toBe(false);
    expect(r.error).toBe('no_agent_client');
  });
});

describe('makeAgentClient — DI over fetch', () => {
  it('POSTs to /scan with the x-agent-token header and returns {status, body}', async () => {
    const fetchImpl = jest.fn(async () => ({
      status: 200,
      json: async () => nucleiBody,
    }));
    const client = makeAgentClient({
      baseUrl: 'http://127.0.0.1:8787',
      token: 'secret',
      fetchImpl,
    });
    const res = await client.scan({
      tool: 'nuclei',
      target: 'app.example.com',
      profile: 'quick',
    });
    expect(res.status).toBe(200);
    expect(res.body).toBe(nucleiBody);
    const [url, opts] = fetchImpl.mock.calls[0];
    expect(url).toBe('http://127.0.0.1:8787/scan');
    expect(opts.method).toBe('POST');
    expect(opts.headers['x-agent-token']).toBe('secret');
    expect(JSON.parse(opts.body)).toEqual({
      tool: 'nuclei',
      target: 'app.example.com',
      profile: 'quick',
    });
  });
});
