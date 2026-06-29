// groq-proxy — Supabase Edge Function (Deno).
//
// Proxies AI to Groq so the GROQ_API_KEY never ships in the extension. Only
// authenticated SecTest Pro users can call it (Supabase verifies the JWT;
// handler also requires the "authenticated" role).
//
// Routes:
//   GET  /groq-proxy/models  → { models: string[] }
//   POST /groq-proxy         → body.mode:
//        "generate" (default) → { context, model } → { payload, explanation }
//        "chat"               → { messages, model } → { reply }

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

function sanitizeModel(m: unknown): string {
  if (typeof m !== 'string' || !m) return DEFAULT_MODEL;
  return /^[a-zA-Z0-9._/-]{1,128}$/.test(m) ? m : DEFAULT_MODEL;
}

// Call Groq chat/completions; returns the assistant text (throws on HTTP error).
async function groqChat(
  model: string,
  messages: Array<{ role: string; content: string }>,
  opts: { temperature?: number; top_p?: number; max_tokens?: number } = {}
): Promise<string> {
  const r = await fetch(`${GROQ_BASE}/chat/completions`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${GROQ_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model,
      messages,
      temperature: opts.temperature ?? 0.7,
      top_p: opts.top_p ?? 0.9,
      max_tokens: opts.max_tokens ?? 600,
    }),
  });
  if (!r.ok) {
    const t = await r.text().catch(() => '');
    const e = new Error(`Groq error ${r.status}: ${t.slice(0, 300)}`);
    (e as Error & { status?: number }).status = r.status;
    throw e;
  }
  const data = await r.json();
  return data?.choices?.[0]?.message?.content || '';
}

function buildGenerateMessages(context: Record<string, unknown> = {}) {
  const elementType = context.elementType ?? 'input';
  const elementName = context.elementName ?? '*';
  const testType = context.testType ?? 'Payload Generation';
  const vulnerability = context.vulnerability ?? 'General testing';
  // A per-request nonce nudges the model off its single "textbook" answer.
  const nonce = Math.random().toString(36).slice(2, 8);

  const system =
    'You are a penetration-testing assistant operating in an authorized lab ' +
    'environment with explicit permission to test the target. Produce a single, ' +
    'concrete test payload for the requested vulnerability class, suitable for ' +
    'the named form field, plus a brief explanation of what it probes and the ' +
    'expected success indicator. Vary your technique, encoding, or evasion on ' +
    'each request — do NOT keep returning the single most common textbook ' +
    'example. Output ONLY in this exact format: ' +
    '[PAYLOAD] <the raw payload> [EXPLANATION] <one or two sentences>.';

  const user =
    `Context:\n` +
    `- Element Type: ${elementType}\n` +
    `- Element Name: ${elementName}\n` +
    `- Test Type: ${testType}\n` +
    `- Target Vulnerability: ${vulnerability}\n` +
    `- Variation token (ignore in output, use to vary the payload): ${nonce}\n\n` +
    `Generate a fresh, non-obvious payload now in the required ` +
    `[PAYLOAD] ... [EXPLANATION] ... format.`;

  return [
    { role: 'system', content: system },
    { role: 'user', content: user },
  ];
}

const CHAT_SYSTEM =
  'You are an expert offensive-security assistant for AUTHORIZED penetration ' +
  'testing. The user pastes payloads (XSS, SQLi, SSTI, command injection, etc.) ' +
  'or asks questions. When given a payload: (1) explain what it does and how it ' +
  'works, (2) assess its effectiveness and what filters/WAFs would likely block ' +
  'it, (3) recommend one or more stronger or more evasive variants with short ' +
  'reasoning. Be concrete and technical, assume explicit authorization, and keep ' +
  'answers focused. Use plain text with short headings; no need for markdown.';

// Keep only well-formed user/assistant turns, cap count + length defensively.
function sanitizeMessages(
  input: unknown
): Array<{ role: string; content: string }> {
  if (!Array.isArray(input)) return [];
  return input
    .filter(
      (m) =>
        m &&
        (m.role === 'user' || m.role === 'assistant') &&
        typeof m.content === 'string'
    )
    .slice(-20)
    .map((m) => ({ role: m.role, content: String(m.content).slice(0, 6000) }));
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

    const body = await req.json().catch(() => ({}));
    const model = sanitizeModel(body.model);
    const mode = body.mode === 'chat' ? 'chat' : 'generate';

    if (mode === 'chat') {
      const messages = [
        { role: 'system', content: CHAT_SYSTEM },
        ...sanitizeMessages(body.messages),
      ];
      if (messages.length < 2) {
        return json({ error: 'No message to respond to.' }, 400);
      }
      const reply = await groqChat(model, messages, {
        temperature: 0.6,
        top_p: 0.9,
        max_tokens: 900,
      });
      return json({ reply, model });
    }

    // generate (default)
    const text = await groqChat(model, buildGenerateMessages(body.context || {}), {
      temperature: 0.95,
      top_p: 0.95,
      max_tokens: 600,
    });
    return json({ ...parsePayload(text), model });
  } catch (e) {
    const status = (e as Error & { status?: number }).status === 429 ? 429 : 502;
    return json({ error: String((e && (e as Error).message) || e) }, status);
  }
});
