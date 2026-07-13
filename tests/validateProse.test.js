import { describe, it, expect, jest } from '@jest/globals';
import {
  fallbackProse,
  sanitizeProse,
  buildProsePrompt,
  explainConfidence,
} from '../src/utils/validateProse';

// Mock the AI provider so the DEFAULT chat path is deterministic and offline:
// omitting the injected chat must still degrade to the fallback, never network.
jest.mock('../src/utils/aiProvider', () => ({
  chat: jest.fn(() => Promise.reject(new Error('no provider in tests'))),
}));

describe('fallbackProse — deterministic offline sentence', () => {
  it('joins band, confidence and reasons into one sentence', () => {
    const s = fallbackProse({
      confidence: 65,
      band: 'likely',
      reasons: [
        'time-based blind SQLi signal observed',
        'timing can be noisy — corroborate',
      ],
    });
    expect(s).toBe(
      'Likely (65%): time-based blind SQLi signal observed; timing can be noisy — corroborate.'
    );
  });

  it('has a sensible default when there are no reasons', () => {
    expect(
      fallbackProse({ confidence: 80, band: 'confirmed', reasons: [] })
    ).toBe('Confirmed (80%): scored from available evidence.');
  });

  it('never throws on missing/invalid validation', () => {
    expect(typeof fallbackProse()).toBe('string');
    expect(typeof fallbackProse(null)).toBe('string');
    expect(fallbackProse({})).toEqual(expect.any(String));
  });
});

describe('sanitizeProse — one line, bounded', () => {
  it('collapses whitespace and newlines to a single line', () => {
    expect(sanitizeProse('  hello\n\n  world \t next ')).toBe(
      'hello world next'
    );
  });

  it('returns empty for empty/whitespace/non-string', () => {
    expect(sanitizeProse('')).toBe('');
    expect(sanitizeProse('   ')).toBe('');
    expect(sanitizeProse(null)).toBe('');
    expect(sanitizeProse(42)).toBe('');
  });

  it('rejects over-length text so the caller can fall back', () => {
    expect(sanitizeProse('x'.repeat(300))).toBe('');
    expect(sanitizeProse('too long', { maxLen: 3 })).toBe('');
  });
});

describe('buildProsePrompt — grounded, rephrase-only', () => {
  const validation = {
    confidence: 45,
    band: 'tentative',
    reasons: ['reflection context: attribute'],
  };

  it('produces a user message grounded in the reasons and the finding type', () => {
    const { messages } = buildProsePrompt({ type: 'dom-xss' }, validation);
    expect(Array.isArray(messages)).toBe(true);
    expect(messages).toHaveLength(1);
    expect(messages[0].role).toBe('user');
    const content = messages[0].content;
    expect(content).toContain('reflection context: attribute'); // the reason
    expect(content).toContain('dom-xss'); // finding type for context
    expect(content).toMatch(/one sentence/i);
  });

  it('instructs the model to add nothing and not change the score', () => {
    const content = buildProsePrompt({ type: 'header' }, validation).messages[0]
      .content;
    expect(content).toMatch(/no new claims|add no/i);
    expect(content).toMatch(/confidence|severity|score/i); // told NOT to touch it
  });

  it('tolerates missing reasons without throwing', () => {
    const { messages } = buildProsePrompt({}, {});
    expect(messages.length).toBeGreaterThan(0);
    expect(messages[0].content).toContain('no specific signals');
  });
});

describe('explainConfidence — orchestrator (injected chat, no network)', () => {
  const finding = { type: 'sqli-time' };
  const validation = {
    confidence: 65,
    band: 'likely',
    reasons: ['time-based blind SQLi signal observed'],
  };

  it('uses a good LLM sentence and marks the source as llm', async () => {
    const chat = jest.fn(
      async () => '  This finding shows a time-based blind SQLi signal.  '
    );
    const r = await explainConfidence(finding, validation, { chat });
    expect(r.source).toBe('llm');
    expect(r.prose).toBe('This finding shows a time-based blind SQLi signal.');
    expect(chat).toHaveBeenCalledTimes(1);
  });

  it('falls back when the LLM returns empty', async () => {
    const r = await explainConfidence(finding, validation, {
      chat: async () => '',
    });
    expect(r.source).toBe('fallback');
    expect(r.prose).toBe(fallbackProse(validation));
  });

  it('falls back (never throws) when the LLM call rejects', async () => {
    const r = await explainConfidence(finding, validation, {
      chat: async () => {
        throw new Error('boom');
      },
    });
    expect(r.source).toBe('fallback');
  });

  it('falls back when the LLM rambles past the length cap', async () => {
    const r = await explainConfidence(finding, validation, {
      chat: async () => 'blah '.repeat(200),
    });
    expect(r.source).toBe('fallback');
  });

  it('uses the default provider when no chat is injected, and still degrades to fallback offline', async () => {
    const r = await explainConfidence(finding, validation);
    expect(r.source).toBe('fallback');
    expect(r.prose).toBe(fallbackProse(validation));
  });
});
