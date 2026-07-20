import { describe, it, expect } from '@jest/globals';
import { adaptivePayloadLoop, buildRefinePrompt, parsePayloadReply, MAX_ROUNDS } from '../src/utils/adaptivePayload';

const vuln = { key: 'xss', label: 'Cross-Site Scripting (XSS)' };
const reply = (p) => `[PAYLOAD] ${p} [EXPLANATION] probes reflection`;

describe('parsePayloadReply', () => {
  it('extracts the payload from the [PAYLOAD] … [EXPLANATION] format', () => {
    expect(parsePayloadReply('[PAYLOAD] <img src=x onerror=1> [EXPLANATION] why')).toBe('<img src=x onerror=1>');
  });
  it('returns empty on a malformed reply and never throws', () => {
    expect(parsePayloadReply('no markers here')).toBe('');
    expect(parsePayloadReply(null)).toBe('');
  });
});

describe('buildRefinePrompt', () => {
  it('grounds the first round and folds prior failed attempts into a refine round', () => {
    const first = buildRefinePrompt(vuln, { framework: 'React', sink: 'innerHTML' }, []);
    expect(first[0].content).toMatch(/React/);
    expect(first[0].content).toMatch(/innerHTML/);
    const refine = buildRefinePrompt(vuln, {}, [{ payload: '<script>', observation: { evidence: 'stripped' } }]);
    expect(refine[0].content).toMatch(/<script>/);
    expect(refine[0].content).toMatch(/stripped/i);
  });

  it('seeds the first round from prior wins, but not once attempts exist', () => {
    const seeded = buildRefinePrompt(vuln, { priorWins: ['<svg onload=1>'] }, []);
    expect(seeded[0].content).toMatch(/worked before/i);
    expect(seeded[0].content).toMatch(/<svg onload=1>/);
    // once there's history, the refine section drives instead of the seed
    const later = buildRefinePrompt(vuln, { priorWins: ['<svg onload=1>'] }, [{ payload: 'x', observation: {} }]);
    expect(later[0].content).not.toMatch(/worked before/i);
  });
});

describe('adaptivePayloadLoop', () => {
  it('stops and returns the winner as soon as observe reports success', async () => {
    const chat = async () => reply('WIN');
    const observe = async (p) => ({ success: p === 'WIN', evidence: 'reflected unescaped' });
    const r = await adaptivePayloadLoop({ vuln, context: {}, chat, observe });
    expect(r.success).toBe(true);
    expect(r.payload).toBe('WIN');
    expect(r.rounds).toBe(1);
  });

  it('refines across rounds, feeding each failure back until success', async () => {
    let n = 0;
    const chat = async () => reply(`try${++n}`);
    const observe = async (p) => ({ success: p === 'try3', evidence: p === 'try3' ? 'hit' : 'filtered' });
    const r = await adaptivePayloadLoop({ vuln, context: {}, chat, observe });
    expect(r.success).toBe(true);
    expect(r.payload).toBe('try3');
    expect(r.rounds).toBe(3);
    expect(r.history).toHaveLength(3);
  });

  it('gives up after MAX_ROUNDS with success=false', async () => {
    const chat = async () => reply('nope');
    const observe = async () => ({ success: false, evidence: 'filtered' });
    const r = await adaptivePayloadLoop({ vuln, context: {}, chat, observe });
    expect(r.success).toBe(false);
    expect(r.rounds).toBe(MAX_ROUNDS);
  });

  it('never throws when chat rejects or observe throws', async () => {
    const r1 = await adaptivePayloadLoop({ vuln, context: {}, chat: async () => { throw new Error('x'); }, observe: async () => ({ success: true }) });
    expect(r1.success).toBe(false);
    const bad = async () => { throw new Error('obs'); };
    const r2 = await adaptivePayloadLoop({ vuln, context: {}, chat: async () => reply('p'), observe: bad });
    expect(r2.success).toBe(false); // observe failure treated as non-success, no throw
  });
});
