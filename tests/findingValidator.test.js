import { describe, it, expect } from '@jest/globals';
import { buildFindingValidationPrompt, validateFinding } from '../src/utils/findingValidator';

const f = { type: 'sqli', host: 'app.example.com', severity: 'high', confidence: 85, matched: "boolean blind on q: 1 AND 1=1 differs from 1 AND 1=2" };

describe('buildFindingValidationPrompt', () => {
  it('includes the finding type, host, and evidence, and asks for a JSON verdict', () => {
    const msgs = buildFindingValidationPrompt(f);
    const c = msgs[0].content;
    expect(c).toContain('sqli');
    expect(c).toContain('app.example.com');
    expect(c).toMatch(/boolean blind/);
    expect(c).toMatch(/false_positive/);
    expect(c).toMatch(/json/i);
  });
});

describe('validateFinding — DI chat', () => {
  it('parses a confirmed verdict', async () => {
    const chat = async () => JSON.stringify({ verdict: 'confirmed', reason: 'clear boolean differential' });
    const v = await validateFinding(f, { chat });
    expect(v.verdict).toBe('confirmed');
    expect(v.source).toBe('llm');
    expect(v.reason).toMatch(/differential/);
  });

  it('flags a false positive', async () => {
    const chat = async () => JSON.stringify({ verdict: 'false_positive', reason: 'generic 500, no differential' });
    const v = await validateFinding({ type: 'sqli', matched: '500 error' }, { chat });
    expect(v.verdict).toBe('false_positive');
  });

  it('defaults to "likely" (keep it) on a throw, bad JSON, or unknown verdict — never drops', async () => {
    expect((await validateFinding(f, { chat: async () => { throw new Error('x'); } })).verdict).toBe('likely');
    expect((await validateFinding(f, { chat: async () => 'not json' })).verdict).toBe('likely');
    expect((await validateFinding(f, { chat: async () => JSON.stringify({ verdict: 'weird' }) })).verdict).toBe('likely');
  });
});
