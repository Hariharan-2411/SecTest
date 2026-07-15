import { describe, it, expect } from '@jest/globals';
import {
  analyzeHandshake,
  isCswshCandidate,
  mergeWsEndpoint,
  mutateFrame,
  buildWsFindings,
} from '../src/utils/websocket';

describe('analyzeHandshake', () => {
  it('extracts host, origin, cookie presence, and same-origin', () => {
    const h = analyzeHandshake({
      url: 'wss://x.com/ws',
      requestHeaders: [
        { name: 'Origin', value: 'https://x.com' },
        { name: 'Cookie', value: 'sid=abc' },
      ],
    });
    expect(h.host).toBe('x.com');
    expect(h.origin).toBe('https://x.com');
    expect(h.hasCookie).toBe(true);
    expect(h.sameOrigin).toBe(true);
  });

  it('detects cross-origin and absent cookie', () => {
    const h = analyzeHandshake({
      url: 'wss://api.x.com/ws',
      requestHeaders: [{ name: 'Origin', value: 'https://evil.com' }],
    });
    expect(h.host).toBe('api.x.com');
    expect(h.hasCookie).toBe(false);
    expect(h.sameOrigin).toBe(false);
  });

  it('is safe for junk input', () => {
    expect(analyzeHandshake(null).url).toBe('');
  });
});

describe('isCswshCandidate', () => {
  it('flags a cookie-authenticated socket with no url token', () => {
    expect(isCswshCandidate({ hasCookie: true, url: 'wss://x.com/ws' })).toBe(true);
  });
  it('is not a candidate when a token is in the url (not ambient-auth)', () => {
    expect(isCswshCandidate({ hasCookie: true, url: 'wss://x.com/ws?token=abc' })).toBe(false);
  });
  it('is not a candidate without cookies', () => {
    expect(isCswshCandidate({ hasCookie: false, url: 'wss://x.com/ws' })).toBe(false);
  });
});

describe('mergeWsEndpoint', () => {
  it('dedupes by url and records the cswsh flag', () => {
    let list = mergeWsEndpoint([], {
      url: 'wss://x.com/ws',
      host: 'x.com',
      origin: 'https://x.com',
      hasCookie: true,
      sameOrigin: true,
    });
    expect(list).toHaveLength(1);
    expect(list[0].cswsh).toBe(true);
    list = mergeWsEndpoint(list, { url: 'wss://x.com/ws', host: 'x.com', hasCookie: true });
    expect(list).toHaveLength(1);
  });

  it('ignores an entry with no url', () => {
    expect(mergeWsEndpoint([], {})).toEqual([]);
  });
});

describe('mutateFrame', () => {
  it('injects the payload into the first string field of a JSON frame', () => {
    expect(mutateFrame('{"msg":"hi","n":1}', '<x>')).toBe('{"msg":"<x>","n":1}');
  });
  it('returns the payload for a non-JSON frame', () => {
    expect(mutateFrame('plaintext', '<x>')).toBe('<x>');
  });
  it('is safe for null frame', () => {
    expect(mutateFrame(null, '<x>')).toBe('<x>');
  });
});

describe('buildWsFindings', () => {
  it('emits a ws-endpoint summary and a ws-cswsh per candidate', () => {
    const f = buildWsFindings({
      host: 'x.com',
      endpoints: [
        { url: 'wss://x.com/ws', origin: 'https://x.com', hasCookie: true, cswsh: true },
      ],
    });
    expect(f.find((x) => x.type === 'ws-endpoint')).toBeTruthy();
    const c = f.find((x) => x.type === 'ws-cswsh');
    expect(c).toBeTruthy();
    expect(c.severity).toBe('low');
    expect(c.source).toBe('ws-recon');
  });

  it('emits ws-injection for provided injection results', () => {
    const f = buildWsFindings({
      host: 'x.com',
      endpoints: [{ url: 'wss://x.com/ws', cswsh: false }],
      injections: [{ url: 'wss://x.com/ws', payload: '<x>', family: 'xss' }],
    });
    expect(f.find((x) => x.type === 'ws-injection')).toBeTruthy();
  });

  it('emits no cswsh finding for a non-candidate socket', () => {
    const f = buildWsFindings({
      host: 'x.com',
      endpoints: [{ url: 'wss://x.com/ws', hasCookie: false, cswsh: false }],
    });
    expect(f.find((x) => x.type === 'ws-cswsh')).toBeFalsy();
    expect(f.find((x) => x.type === 'ws-endpoint')).toBeTruthy();
  });

  it('returns nothing with no endpoints', () => {
    expect(buildWsFindings({ host: 'x.com', endpoints: [] })).toEqual([]);
  });
});
