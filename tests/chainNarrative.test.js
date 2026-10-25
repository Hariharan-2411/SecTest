import { describe, it, expect } from '@jest/globals';
import { buildChainNarrativePrompt, draftChainNarrative } from '../src/utils/chainNarrative';

const chain = {
  id: 'chn_1',
  title: 'DOM-XSS → exposed token → account takeover',
  steps: [{ findingId: 'a', type: 'dom-xss' }, { findingId: 'b', type: 'jwt' }],
  findingIds: ['a', 'b'],
  severity: 'high',
  rationale: 'XSS can exfiltrate the exposed token',
  hosts: ['app.example.com'],
};

describe('buildChainNarrativePrompt', () => {
  it('grounds on the title, steps, and severity, and forbids changing severity', () => {
    const content = buildChainNarrativePrompt(chain)[0].content;
    expect(content).toContain('DOM-XSS → exposed token → account takeover');
    expect(content).toMatch(/dom-xss → jwt/);
    expect(content).toMatch(/high/);
    expect(content).toMatch(/do not change/i);
  });
});

describe('draftChainNarrative', () => {
  it('drafts impact prose but keeps the code-owned severity', async () => {
    const chat = async () => JSON.stringify({ summary: 's', impact: 'i', remediation: 'r', cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', severity: 'critical' });
    const r = await draftChainNarrative(chain, { chat });
    expect(r.source).toBe('llm');
    expect(r.summary).toBe('s');
    expect(r.impact).toBe('i');
    expect(r.remediation).toBe('r');
    expect(r.cvss).toMatch(/^CVSS:3\.1\//);
    expect(r.severity).toBe('high'); // AUTHORITATIVE — the model's "critical" is ignored
  });

  it('drops an invalid CVSS vector to null and never lets the model set severity', async () => {
    const chat = async () => JSON.stringify({ summary: 's', impact: 'i', cvss: 'not-a-vector', severity: 'critical' });
    const r = await draftChainNarrative(chain, { chat });
    expect(r.cvss).toBeNull();
    expect(r.severity).toBe('high');
  });

  it('refuses a chain with fewer than two steps (no LLM call)', async () => {
    let called = false;
    const chat = async () => { called = true; return '{}'; };
    const r = await draftChainNarrative({ ...chain, steps: [chain.steps[0]] }, { chat });
    expect(r.source).toBe('error');
    expect(called).toBe(false);
  });

  it('never throws when chat rejects or returns junk', async () => {
    const thrown = await draftChainNarrative(chain, { chat: async () => { throw new Error('x'); } });
    expect(thrown.source).toBe('error');
    expect(thrown.severity).toBe('high');
    const junk = await draftChainNarrative(chain, { chat: async () => 'not json' });
    expect(junk.source).toBe('error');
  });
});
