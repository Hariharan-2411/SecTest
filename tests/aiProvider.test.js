import { describe, it, expect, jest, beforeEach } from '@jest/globals';

jest.mock('../src/config', () => ({
  EDGE_FN_URL: 'https://proj.supabase.co/functions/v1/groq-proxy',
  SUPABASE_ANON_KEY: 'anon-key',
  isConfigured: () => true,
}));
jest.mock('../src/utils/auth', () => ({ getAccessToken: jest.fn() }));

import { getAccessToken } from '../src/utils/auth';
import * as ai from '../src/utils/aiProvider';
import { decorate, MODEL_HINTS, DEFAULT_MODEL } from '../src/utils/aiModels';

const okJson = (data) => ({ ok: true, json: async () => data });
const errJson = (status, data) => ({ ok: false, status, json: async () => data });

describe('aiProvider', () => {
  beforeEach(() => {
    getAccessToken.mockResolvedValue('jwt-token');
    global.fetch = jest.fn();
  });

  it('generatePayload posts to the proxy with auth headers + body and parses the result', async () => {
    global.fetch.mockResolvedValue(okJson({ payload: '<script>', explanation: 'XSS probe', model: 'llama-3.3-70b-versatile' }));
    const out = await ai.generatePayload({ vulnerability: 'XSS' }, 'llama-3.3-70b-versatile');

    const [url, opts] = global.fetch.mock.calls[0];
    expect(url).toBe('https://proj.supabase.co/functions/v1/groq-proxy');
    expect(opts.method).toBe('POST');
    expect(opts.headers.Authorization).toBe('Bearer jwt-token');
    expect(opts.headers.apikey).toBe('anon-key');
    expect(JSON.parse(opts.body)).toEqual({ context: { vulnerability: 'XSS' }, model: 'llama-3.3-70b-versatile' });
    expect(out).toEqual({ payload: '<script>', explanation: 'XSS probe', model: 'llama-3.3-70b-versatile' });
  });

  it('throws NOT_AUTHENTICATED when there is no token', async () => {
    getAccessToken.mockResolvedValue(null);
    await expect(ai.generatePayload({}, 'm')).rejects.toMatchObject({ code: 'NOT_AUTHENTICATED' });
    expect(global.fetch).not.toHaveBeenCalled();
  });

  it('surfaces the proxy error message and status on failure', async () => {
    global.fetch.mockResolvedValue(errJson(429, { error: 'Groq error 429: rate limited' }));
    await expect(ai.generatePayload({}, 'm')).rejects.toMatchObject({
      message: 'Groq error 429: rate limited',
      status: 429,
    });
  });

  it('chat posts mode=chat with the message history and returns the reply', async () => {
    global.fetch.mockResolvedValue(okJson({ reply: 'That payload triggers XSS…', model: 'm' }));
    const msgs = [{ role: 'user', content: 'explain <script>alert(1)</script>' }];
    const reply = await ai.chat(msgs, 'llama-3.3-70b-versatile');

    const [url, opts] = global.fetch.mock.calls[0];
    expect(url).toBe('https://proj.supabase.co/functions/v1/groq-proxy');
    expect(opts.method).toBe('POST');
    expect(JSON.parse(opts.body)).toEqual({ mode: 'chat', messages: msgs, model: 'llama-3.3-70b-versatile' });
    expect(reply).toBe('That payload triggers XSS…');
  });

  it('listModels GETs /models and returns the id array', async () => {
    global.fetch.mockResolvedValue(okJson({ models: ['llama-3.3-70b-versatile', 'gemma2-9b-it'] }));
    const ids = await ai.listModels();
    const [url, opts] = global.fetch.mock.calls[0];
    expect(url).toBe('https://proj.supabase.co/functions/v1/groq-proxy/models');
    expect(opts.method).toBe('GET');
    expect(ids).toEqual(['llama-3.3-70b-versatile', 'gemma2-9b-it']);
  });

  it('checkReachable is true on success and false on failure', async () => {
    global.fetch.mockResolvedValue(okJson({ models: ['x'] }));
    expect(await ai.checkReachable()).toBe(true);
    global.fetch.mockResolvedValue(errJson(401, { error: 'nope' }));
    expect(await ai.checkReachable()).toBe(false);
  });
});

describe('aiModels.decorate', () => {
  it('labels known ids from the hint map', () => {
    const out = decorate(['llama-3.3-70b-versatile']);
    expect(out[0]).toEqual({
      id: 'llama-3.3-70b-versatile',
      label: MODEL_HINTS['llama-3.3-70b-versatile'].label,
      tier: 'recommended',
    });
  });

  it('passes unknown/new ids through with their raw name', () => {
    const out = decorate(['brand-new-model-2027']);
    expect(out[0]).toEqual({ id: 'brand-new-model-2027', label: 'brand-new-model-2027', tier: 'other' });
  });

  it('falls back to the hint-map keys when the live list is empty', () => {
    const out = decorate([]);
    expect(out.length).toBe(Object.keys(MODEL_HINTS).length);
    expect(out.some((m) => m.id === DEFAULT_MODEL)).toBe(true);
  });
});
