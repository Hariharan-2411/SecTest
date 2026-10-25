import { describe, it, expect } from '@jest/globals';
import { diffResponses, looksInteresting, buildAccessControlPrompt, analyzeAccessControl } from '../src/utils/responseDiff';

const mine = { status: 200, body: '{"user":"me","email":"me@x.com","balance":100}' };
const neighbor = { status: 200, body: '{"user":"other","email":"other@x.com","balance":9999}' };
const denied = { status: 403, body: 'Forbidden' };

describe('diffResponses', () => {
  it('captures status, length, identical-body, and both-ok', () => {
    const d = diffResponses(mine, neighbor);
    expect(d.statusA).toBe(200);
    expect(d.statusB).toBe(200);
    expect(d.identicalBody).toBe(false);
    expect(d.bothOk).toBe(true);
    expect(d.lenDelta).toBeGreaterThan(0);
  });
  it('never throws on garbage', () => {
    expect(() => diffResponses(null, undefined)).not.toThrow();
    expect(diffResponses(null, null).bothOk).toBe(false);
  });
});

describe('looksInteresting', () => {
  it('flags two OK-but-different responses and rejects denials or identical bodies', () => {
    expect(looksInteresting(diffResponses(mine, neighbor))).toBe(true);
    expect(looksInteresting(diffResponses(mine, denied))).toBe(false);
    expect(looksInteresting(diffResponses(mine, mine))).toBe(false); // identical
  });
});

describe('diffResponses — length-only (F2, the real replay shape)', () => {
  it('diffs on length when only status+length are given (no bodies fetched)', () => {
    const d = diffResponses({ status: 200, length: 500 }, { status: 200, length: 1200 });
    expect(d.lenA).toBe(500);
    expect(d.lenB).toBe(1200);
    expect(d.divergent).toBe(true);
    expect(d.bothOk).toBe(true);
    expect(looksInteresting(d)).toBe(true);
  });
  it('equal lengths are not divergent', () => {
    expect(looksInteresting(diffResponses({ status: 200, length: 300 }, { status: 200, length: 300 }))).toBe(false);
  });
  it('body findings still work via the divergent flag', () => {
    expect(diffResponses(mine, neighbor).divergent).toBe(true);
    expect(diffResponses(mine, mine).divergent).toBe(false);
  });
});

describe('buildAccessControlPrompt — privacy', () => {
  it('sends metadata only, never the raw response bodies', () => {
    const content = buildAccessControlPrompt(diffResponses(mine, neighbor), { endpoint: '/api/users/1' })[0].content;
    expect(content).toMatch(/status=200/);
    expect(content).not.toContain('other@x.com'); // no raw body leaked
    expect(content).not.toContain('balance');
  });
});

describe('analyzeAccessControl', () => {
  it('short-circuits deterministically (no LLM) when responses do not diverge', async () => {
    let called = false;
    const chat = async () => { called = true; return '{}'; };
    const r = await analyzeAccessControl({ a: mine, b: mine, chat });
    expect(r.candidate).toBe(false);
    expect(r.source).toBe('deterministic');
    expect(called).toBe(false);
  });

  it('drafts an IDOR candidate from the LLM when the diff is interesting', async () => {
    const chat = async () => JSON.stringify({ candidate: true, kind: 'idor', confidence: 72, rationale: 'B returns a different user record' });
    const r = await analyzeAccessControl({ a: mine, b: neighbor, context: { endpoint: '/api/users/1' }, chat });
    expect(r.candidate).toBe(true);
    expect(r.kind).toBe('idor');
    expect(r.confidence).toBe(72);
    expect(r.source).toBe('llm');
  });

  it('never leaks the raw bodies to the injected chat', async () => {
    let seen = '';
    const chat = async (messages) => { seen = JSON.stringify(messages); return '{"candidate":false,"kind":"none","confidence":0,"rationale":"x"}'; };
    await analyzeAccessControl({ a: mine, b: neighbor, chat });
    expect(seen).not.toContain('other@x.com');
    expect(seen).not.toContain('me@x.com');
  });

  it('auth variant: both-2xx is interesting even when similar (missing-auth), and a denial is not', async () => {
    const chat = async () => JSON.stringify({ candidate: true, kind: 'logic', confidence: 60, rationale: 'anon reached authenticated content' });
    // authed vs anon, both 200, SIMILAR length → not divergent, but auth-variant flags it
    const hit = await analyzeAccessControl({ a: { status: 200, length: 500 }, b: { status: 200, length: 500 }, variant: 'auth', chat });
    expect(hit.source).toBe('llm');
    expect(hit.candidate).toBe(true);
    // a proper 403 denial short-circuits deterministically (no LLM)
    let called = false;
    const chat2 = async () => { called = true; return '{}'; };
    const denied2 = await analyzeAccessControl({ a: { status: 200, length: 500 }, b: { status: 403, length: 20 }, variant: 'auth', chat: chat2 });
    expect(denied2.source).toBe('deterministic');
    expect(called).toBe(false);
  });

  it('sanitizes a bad kind and never throws when chat fails or returns junk', async () => {
    const bad = await analyzeAccessControl({ a: mine, b: neighbor, chat: async () => JSON.stringify({ candidate: true, kind: 'nonsense', confidence: 999 }) });
    expect(bad.kind).toBe('none');
    expect(bad.candidate).toBe(false); // kind none → not a candidate
    const thrown = await analyzeAccessControl({ a: mine, b: neighbor, chat: async () => { throw new Error('x'); } });
    expect(thrown.source).toBe('error');
    const junk = await analyzeAccessControl({ a: mine, b: neighbor, chat: async () => 'not json' });
    expect(junk.source).toBe('error');
  });
});
