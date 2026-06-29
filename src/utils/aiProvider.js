import { getAccessToken } from './auth';
import { EDGE_FN_URL, SUPABASE_ANON_KEY } from '../config';
import { DEFAULT_MODEL } from './aiModels';

// Client for the groq-proxy Edge Function. Sends the logged-in user's JWT (plus
// the anon apikey the gateway expects) so the Groq key stays server-side. Keeps
// the same { payload, explanation } shape the popup already consumes.

const TIMEOUT_MS = 25000;

async function callEdge(path, { method = 'GET', body } = {}) {
  const token = await getAccessToken();
  if (!token) {
    const err = new Error('You must be logged in to use AI.');
    err.code = 'NOT_AUTHENTICATED';
    throw err;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(EDGE_FN_URL + path, {
      method,
      headers: {
        'Content-Type': 'application/json',
        apikey: SUPABASE_ANON_KEY,
        Authorization: `Bearer ${token}`,
      },
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const err = new Error(
        (data && data.error) || `AI request failed (${res.status})`
      );
      err.status = res.status;
      throw err;
    }
    return data;
  } catch (e) {
    if (e && e.name === 'AbortError') {
      const err = new Error('AI request timed out.');
      err.code = 'TIMEOUT';
      throw err;
    }
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

export async function generatePayload(context, model = DEFAULT_MODEL) {
  const data = await callEdge('', { method: 'POST', body: { context, model } });
  return {
    payload: data.payload || '',
    explanation: data.explanation || '',
    model: data.model || model,
  };
}

export async function listModels() {
  const data = await callEdge('/models', { method: 'GET' });
  return Array.isArray(data.models) ? data.models : [];
}

// Reachability probe for the status indicator. Returns true only if the proxy
// answered successfully (auth ok, Groq reachable).
export async function checkReachable() {
  try {
    await listModels();
    return true;
  } catch (_) {
    return false;
  }
}
