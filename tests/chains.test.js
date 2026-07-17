import { describe, it, expect, jest } from '@jest/globals';
import {
  normalizeChains,
  deriveSeverity,
  validateCvss,
  buildChainsPrompt,
  proposeChains,
  MAX_CHAINS,
  MAX_STEPS,
} from '../src/utils/chains';

// Mock the AI provider so the DEFAULT chat path is deterministic and offline.
jest.mock('../src/utils/aiProvider', () => ({
  chat: jest.fn(() => Promise.reject(new Error('no provider in tests'))),
}));

const scope = { inScope: ['*.example.com', 'example.com'], outOfScope: [] };

// Findings carry explicit confidence so the pure layer reads it directly.
const f1 = {
  id: 'f1',
  type: 'sqli-boolean',
  severity: 'high',
  host: 'app.example.com',
  title: 'SQLi',
  confidence: 80,
};
const f2 = {
  id: 'f2',
  type: 'dom-xss',
  severity: 'medium',
  host: 'app.example.com',
  title: 'DOM XSS',
  confidence: 55,
};

describe('deriveSeverity — deterministic, model has no say', () => {
  it('takes the strongest constituent and bumps one level, capped at critical', () => {
    expect(deriveSeverity([{ severity: 'medium' }, { severity: 'high' }])).toBe(
      'critical'
    );
    expect(deriveSeverity([{ severity: 'low' }, { severity: 'low' }])).toBe(
      'medium'
    );
    expect(
      deriveSeverity([{ severity: 'critical' }, { severity: 'low' }])
    ).toBe('critical');
    expect(deriveSeverity([{ severity: 'informational' }])).toBe('low');
  });
  it('is safe on empty input', () => {
    expect(deriveSeverity([])).toBe('informational');
  });
});

describe('validateCvss — format-check only', () => {
  it('accepts a well-formed CVSS 3.1 vector and rejects anything else', () => {
    const v = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H';
    expect(validateCvss(v)).toBe(v);
    expect(validateCvss('high')).toBeNull();
    expect(validateCvss('CVSS:2.0/AV:N')).toBeNull();
    expect(validateCvss(null)).toBeNull();
  });
});

describe('normalizeChains — the "never trust the model" gate', () => {
  const findings = [f1, f2];

  it('keeps a grounded 2-step chain, copying type from the real finding', () => {
    const raw = {
      chains: [
        {
          title: 'SQLi + XSS',
          steps: [
            { findingId: 'f1', note: 'dump' },
            { findingId: 'f2', note: 'exec' },
          ],
          cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
          rationale: 'chain them',
        },
      ],
    };
    const { chains, rejected } = normalizeChains(raw, { findings, scope });
    expect(chains).toHaveLength(1);
    expect(chains[0].steps).toHaveLength(2);
    expect(chains[0].steps[0].type).toBe('sqli-boolean'); // copied from the real finding
    expect(chains[0].severity).toBe('critical'); // high bumped
    expect(chains[0].aiCvss).toMatch(/^CVSS:3\.1\//);
    expect(rejected).toHaveLength(0);
  });

  it('drops steps that reference an invented finding, rejecting a chain left with < 2 steps', () => {
    const raw = {
      chains: [{ steps: [{ findingId: 'f1' }, { findingId: 'ghost' }] }],
    };
    const { chains, rejected } = normalizeChains(raw, { findings, scope });
    expect(chains).toHaveLength(0);
    expect(rejected).toHaveLength(1);
  });

  it('rejects a single-step "chain"', () => {
    const { chains } = normalizeChains(
      { chains: [{ steps: [{ findingId: 'f1' }] }] },
      { findings, scope }
    );
    expect(chains).toHaveLength(0);
  });

  it('drops an out-of-scope finding host', () => {
    const evil = {
      id: 'e1',
      type: 'dom-xss',
      severity: 'high',
      host: 'evil.com',
      confidence: 80,
    };
    const raw = {
      chains: [{ steps: [{ findingId: 'f1' }, { findingId: 'e1' }] }],
    };
    const { chains, rejected } = normalizeChains(raw, {
      findings: [f1, evil],
      scope,
    });
    expect(chains).toHaveLength(0); // e1 dropped -> only 1 grounded step -> rejected
    expect(rejected).toHaveLength(1);
  });

  it('refuses to chain a noise-band finding', () => {
    const noise = {
      id: 'n1',
      type: 'dom-xss',
      severity: 'low',
      host: 'app.example.com',
      confidence: 10,
    };
    const raw = {
      chains: [{ steps: [{ findingId: 'f1' }, { findingId: 'n1' }] }],
    };
    const { chains } = normalizeChains(raw, { findings: [f1, noise], scope });
    expect(chains).toHaveLength(0); // n1 is noise -> dropped
  });

  it('caps steps per chain at MAX_STEPS', () => {
    const steps = Array.from({ length: MAX_STEPS + 3 }, () => ({
      findingId: 'f1',
    }));
    const { chains } = normalizeChains(
      { chains: [{ steps }] },
      { findings, scope }
    );
    expect(chains[0].steps).toHaveLength(MAX_STEPS);
  });

  it('caps the number of chains at MAX_CHAINS', () => {
    const one = { steps: [{ findingId: 'f1' }, { findingId: 'f2' }] };
    const raw = { chains: Array.from({ length: MAX_CHAINS + 2 }, () => one) };
    const { chains, rejected } = normalizeChains(raw, { findings, scope });
    expect(chains).toHaveLength(MAX_CHAINS);
    expect(rejected.some((r) => r.reason === 'over_cap')).toBe(true);
  });

  it('sanitizes the rationale to a single bounded line', () => {
    const raw = {
      chains: [
        {
          steps: [{ findingId: 'f1' }, { findingId: 'f2' }],
          rationale: 'line one\n\nline two   spaced',
        },
      ],
    };
    const { chains } = normalizeChains(raw, { findings, scope });
    expect(chains[0].rationale).toBe('line one line two spaced');
  });

  it('tolerates junk input without throwing', () => {
    expect(normalizeChains(null, { findings, scope })).toEqual({
      chains: [],
      rejected: [],
    });
    expect(
      normalizeChains({ chains: 'nope' }, { findings, scope }).chains
    ).toEqual([]);
  });
});

describe('buildChainsPrompt — grounded, bounded, JSON-only', () => {
  it('lists finding ids and instructs reference-only JSON output', () => {
    const { messages } = buildChainsPrompt([f1, f2]);
    expect(messages).toHaveLength(1);
    expect(messages[0].role).toBe('user');
    const c = messages[0].content;
    expect(c).toContain('id=f1');
    expect(c).toContain('id=f2');
    expect(c).toMatch(/json/i);
    expect(c).toMatch(/only the finding ids|do not invent|reference/i);
    expect(c).toMatch(/two steps|at least two/i);
  });

  it('bounds the context to at most 30 findings', () => {
    const many = Array.from({ length: 35 }, (_, i) => ({
      id: `x${i}`,
      type: 'header',
      severity: 'low',
      host: 'a.example.com',
      title: 't',
      confidence: 40,
    }));
    const c = buildChainsPrompt(many).messages[0].content;
    const count = (c.match(/id=x/g) || []).length;
    expect(count).toBeLessThanOrEqual(30);
  });
});

describe('proposeChains — orchestrator (injected chat, no network)', () => {
  const findings = [f1, f2];

  it('parses a valid JSON reply into grounded chains and marks source llm', async () => {
    const reply = JSON.stringify({
      chains: [
        {
          title: 'x',
          steps: [{ findingId: 'f1' }, { findingId: 'f2' }],
          cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
          rationale: 'r',
        },
      ],
    });
    const r = await proposeChains(findings, { chat: async () => reply, scope });
    expect(r.source).toBe('llm');
    expect(r.chains).toHaveLength(1);
    expect(r.chains[0].steps[0].type).toBe('sqli-boolean');
  });

  it('extracts JSON even when the model wraps it in a ```json fence', async () => {
    const reply =
      '```json\n' +
      JSON.stringify({
        chains: [{ steps: [{ findingId: 'f1' }, { findingId: 'f2' }] }],
      }) +
      '\n```';
    const r = await proposeChains(findings, { chat: async () => reply, scope });
    expect(r.source).toBe('llm');
    expect(r.chains).toHaveLength(1);
  });

  it('drops a chain that cites a nonexistent finding', async () => {
    const reply = JSON.stringify({
      chains: [{ steps: [{ findingId: 'f1' }, { findingId: 'ghost' }] }],
    });
    const r = await proposeChains(findings, { chat: async () => reply, scope });
    expect(r.source).toBe('llm');
    expect(r.chains).toHaveLength(0);
    expect(r.rejected.length).toBeGreaterThan(0);
  });

  it('returns source error (no throw) on a non-JSON reply', async () => {
    const r = await proposeChains(findings, {
      chat: async () => 'sorry, no chains found',
      scope,
    });
    expect(r.source).toBe('error');
    expect(r.chains).toEqual([]);
  });

  it('returns source error (no throw) when the chat call rejects', async () => {
    const r = await proposeChains(findings, {
      chat: async () => {
        throw new Error('boom');
      },
      scope,
    });
    expect(r.source).toBe('error');
  });

  it('uses the default provider when no chat is injected, degrading to error offline', async () => {
    const r = await proposeChains(findings, { scope });
    expect(r.source).toBe('error');
    expect(r.chains).toEqual([]);
  });
});

describe('chain playbooks wiring', () => {
  const pbScope = { inScope: ['*.example.com', 'example.com'], outOfScope: [] };
  // Confidence is recomputed by validateFindings, so give real evidence:
  //   dom-xss with html-body reflection -> 75; jwt secret -> 50 (both >= tentative).
  const fXss = { id: 'a', type: 'dom-xss', severity: 'medium', host: 'app.example.com', title: 'XSS', reflection: 'html-body' };
  const fJwt = { id: 'b', type: 'jwt', severity: 'high', host: 'app.example.com', title: 'JWT in JS' };

  it('emits a deterministic chain from a complete playbook even when the LLM fails', async () => {
    const r = await proposeChains([fXss, fJwt], {
      chat: async () => { throw new Error('offline'); },
      scope: pbScope,
    });
    expect(r.source).toBe('playbook');
    expect(r.chains).toHaveLength(1);
    expect([...r.chains[0].findingIds].sort()).toEqual(['a', 'b']);
    expect(r.chains[0].severity).toBe('critical');
  });

  it('buildChainsPrompt appends a grounding block for partial matches', () => {
    const partial = [
      { playbookId: 'xss-secret-ato', name: 'DOM-XSS → exposed token → account takeover', complete: false,
        satisfied: [{ linkId: 'xss', findingId: 'a', type: 'dom-xss' }],
        missing: [{ linkId: 'token', label: 'Exposed token/secret', match: { types: ['jwt'] } }] },
    ];
    const content = buildChainsPrompt([fXss], { playbookMatches: partial }).messages[0].content;
    expect(content).toMatch(/partially matched/i);
    expect(content).toContain('DOM-XSS → exposed token → account takeover');
    expect(content).toContain('token');
  });

  it('buildChainsPrompt is unchanged when called with no playbook matches', () => {
    const content = buildChainsPrompt([fXss]).messages[0].content;
    expect(content).not.toMatch(/partially matched/i);
  });
});
