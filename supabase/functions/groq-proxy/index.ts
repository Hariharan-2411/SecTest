// groq-proxy — Supabase Edge Function (Deno).
//
// Proxies AI payload generation to Groq so the GROQ_API_KEY never ships in the
// extension. Only authenticated SecTest Pro users can call it: the platform
// verifies the Supabase JWT (verify_jwt = true in config.toml) and this handler
// additionally requires the "authenticated" role (rejects the anon key).
//
// Routes:
//   POST  /groq-proxy          → { context, model } → { payload, explanation }
//   GET   /groq-proxy/models   → { models: string[] }  (live Groq model list)

const GROQ_API_KEY = Deno.env.get('GROQ_API_KEY') ?? '';
const GROQ_BASE = 'https://api.groq.com/openai/v1';
const DEFAULT_MODEL = 'llama-3.3-70b-versatile';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers':
    'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}

// Read JWT claims. The platform has already verified the signature (verify_jwt),
// so we only decode the payload to inspect the role/subject.
function decodeJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const part = token.split('.')[1];
    const b64 = part.replace(/-/g, '+').replace(/_/g, '/');
    const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
    return JSON.parse(atob(padded));
  } catch {
    return null;
  }
}

// Only allow a sane model-id shape; fall back to the default otherwise. We do
// NOT hardcode an allowlist (Groq deprecates models) — invalid ids are rejected
// by Groq itself and surfaced as an error.
function sanitizeModel(m: unknown): string {
  if (typeof m !== 'string' || !m) return DEFAULT_MODEL;
  return /^[a-zA-Z0-9._/-]{1,128}$/.test(m) ? m : DEFAULT_MODEL;
}

function buildMessages(context: Record<string, unknown> = {}) {
  const elementType = context.elementType ?? 'input';
  const elementName = context.elementName ?? '*';
  const testType = context.testType ?? 'Payload Generation';
  const vulnerability = context.vulnerability ?? 'General testing';

  const system =
    'You are a penetration-testing assistant operating in an authorized lab ' +
    'environment with explicit permission to test the target. Produce a single, ' +
    'concrete test payload string for the requested vulnerability class, suitable ' +
    'for injecting into the named form field, plus a brief explanation of what it ' +
    'probes and the expected indicator of success. Output ONLY in this exact ' +
    'format: [PAYLOAD] <the raw payload> [EXPLANATION] <one or two sentences>.';

  const user =
    `Context:\n` +
    `- Element Type: ${elementType}\n` +
    `- Element Name: ${elementName}\n` +
    `- Test Type: ${testType}\n` +
    `- Target Vulnerability: ${vulnerability}\n\n` +
    `Generate the payload now in the required [PAYLOAD] ... [EXPLANATION] ... format.`;

  return [
    { role: 'system', content: system },
    { role: 'user', content: user },
  ];
}

function parsePayload(text: string) {
  const p = text.match(/\[PAYLOAD\](.*?)\[EXPLANATION\]/s);
  const e = text.match(/\[EXPLANATION\](.*?)$/s);
  return {
    payload: p ? p[1].trim() : text.trim(),
    explanation: e ? e[1].trim() : 'No explanation provided',
    rawResponse: text,
  };
}

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders });
  }

  if (!GROQ_API_KEY) {
    return json({ error: 'Server is missing GROQ_API_KEY.' }, 500);
  }

  // Require an authenticated user (not the anon key).
  const authHeader = req.headers.get('Authorization') || '';
  if (!authHeader.startsWith('Bearer ')) {
    return json({ error: 'Missing Authorization header.' }, 401);
  }
  const claims = decodeJwtPayload(authHeader.slice(7));
  if (!claims || claims.role !== 'authenticated' || !claims.sub) {
    return json({ error: 'Authentication required.' }, 401);
  }

  const url = new URL(req.url);

  try {
    // ── GET /models ───────────────────────────────────────────
    if (url.pathname.endsWith('/models')) {
      const r = await fetch(`${GROQ_BASE}/models`, {
        headers: { Authorization: `Bearer ${GROQ_API_KEY}` },
      });
      if (!r.ok) return json({ error: `Groq models error: ${r.status}` }, 502);
      const data = await r.json();
      const models = (data.data || [])
        .map((m: { id: string }) => m.id)
        .filter(Boolean);
      return json({ models });
    }

    // ── POST generate ─────────────────────────────────────────
    const body = await req.json().catch(() => ({}));
    const model = sanitizeModel(body.model);

    const r = await fetch(`${GROQ_BASE}/chat/completions`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${GROQ_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model,
        messages: buildMessages(body.context || {}),
        temperature: 0.7,
        top_p: 0.9,
        max_tokens: 600,
      }),
    });

    if (!r.ok) {
      const t = await r.text().catch(() => '');
      const status = r.status === 429 ? 429 : 502;
      return json({ error: `Groq error ${r.status}: ${t.slice(0, 300)}` }, status);
    }

    const data = await r.json();
    const text = data?.choices?.[0]?.message?.content || '';
    return json({ ...parsePayload(text), model });
  } catch (e) {
    return json({ error: String((e && (e as Error).message) || e) }, 500);
  }
});
