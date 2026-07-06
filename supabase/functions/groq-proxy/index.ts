// @ts-nocheck — runs on Deno (Supabase Edge runtime); the `Deno` global resolves
// at deploy time, not in the editor's Node TypeScript server. This file is not
// part of the extension's webpack/jest build.
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
//        "triage"             → { request, response, context } → { likelyVuln, severity, reason }
//        "report"             → { evidence } → { summary, steps, impact, remediation }

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

// Extract the first JSON object from a model reply (models sometimes wrap it in
// prose or code fences). Returns {} when nothing parses.
function parseJsonLoose(text: string): Record<string, unknown> {
  const m = String(text || '').match(/\{[\s\S]*\}/);
  if (!m) return {};
  try {
    return JSON.parse(m[0]);
  } catch {
    return {};
  }
}

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'];
function sanitizeSeverity(s: unknown): string {
  return typeof s === 'string' && SEVERITIES.includes(s) ? s : 'informational';
}

// Bound arbitrary caller-supplied evidence so a huge paste can't blow the prompt.
function clampText(v: unknown, max = 4000): string {
  return typeof v === 'string' ? v.slice(0, max) : JSON.stringify(v ?? '').slice(0, max);
}

const TRIAGE_SYSTEM =
  'You are a security triage assistant for AUTHORIZED penetration testing. ' +
  'Given a captured request, response, and context, judge whether they evidence ' +
  'a real vulnerability. Be CONSERVATIVE: if the evidence is weak or ambiguous, ' +
  'say likelyVuln=false. Respond with ONLY compact JSON, no prose: ' +
  '{"likelyVuln": true|false, "severity": "critical|high|medium|low|informational", ' +
  '"reason": "<one or two sentences citing the evidence>"}.';

const REPORT_SYSTEM =
  'You draft vulnerability-report sections for AUTHORIZED testing, using ONLY the ' +
  'provided evidence. Never invent hosts, parameters, or impact beyond what the ' +
  'evidence supports. Respond with ONLY compact JSON, no prose: ' +
  '{"summary": "<2-4 sentences>", "steps": ["<step>", "..."], ' +
  '"impact": "<realistic impact>", "remediation": "<concrete fix>"}.';

const ESCALATE_SYSTEM =
  'You are an escalation planner for AUTHORIZED penetration testing. Given a ' +
  'finding and the already-mapped IN-SCOPE attack surface, propose concrete NEXT ' +
  'TESTS to confirm or escalate it. Rules: ' +
  '(1) Output ONLY compact JSON, no prose: {"steps":[{"type":"...","target":"...",' +
  '"param":"...","payloadFamily":"...","tool":"...","rationale":"...",' +
  '"expectedSignal":"..."}]}. ' +
  '(2) "type" MUST be one of exactly: deep_js, confirm_reflection, probe_endpoint, ' +
  'run_payload, differential_probe, agent_scan, manual. Use no other verb. ' +
  '(3) Only reference targets/endpoints/params that appear in the provided ' +
  'context; NEVER invent hosts or endpoints. ' +
  '(4) Prefer a read-only confirmation step (probe_endpoint / confirm_reflection / ' +
  'deep_js) before any active step. ' +
  '(5) payloadFamily (only for run_payload) is one of: xss, sqli, cmdi, ' +
  'pathTraversal, ssrf, xpath, ldap. tool (only for agent_scan) is a recon tool ' +
  'name. ' +
  '(6) For anything needing human judgement (IDOR, auth/business logic) use ' +
  'type "manual" and put clear by-hand steps in rationale. ' +
  '(7) NEVER propose data exfiltration, persistence, lateral movement, account ' +
  'takeover of real users, or denial of service. ' +
  '(8) At most 8 steps, highest-value first, each with a one-line rationale and ' +
  'the expectedSignal that would confirm it.';

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
    const validModes = ['chat', 'triage', 'report', 'escalate'];
    const mode = validModes.includes(body.mode) ? body.mode : 'generate';

    if (mode === 'escalate') {
      const user =
        `Finding:\n${clampText(body.finding, 1500)}\n\n` +
        `In-scope attack surface (context):\n${clampText(body.context, 4000)}\n\n` +
        `Return the escalation steps JSON now.`;
      const text = await groqChat(
        model,
        [{ role: 'system', content: ESCALATE_SYSTEM }, { role: 'user', content: user }],
        { temperature: 0.3, top_p: 0.9, max_tokens: 900 }
      );
      const parsed = parseJsonLoose(text);
      const steps = Array.isArray(parsed.steps)
        ? parsed.steps.filter((s) => s && typeof s === 'object').slice(0, 12)
        : [];
      // Note: this is a PROPOSAL only. The extension re-validates every step
      // (allowlist + scope) before anything can run.
      return json({ steps, model });
    }

    if (mode === 'triage') {
      const user =
        `Request:\n${clampText(body.request)}\n\n` +
        `Response:\n${clampText(body.response)}\n\n` +
        `Context:\n${clampText(body.context, 1000)}\n\n` +
        `Return the triage JSON now.`;
      const text = await groqChat(
        model,
        [{ role: 'system', content: TRIAGE_SYSTEM }, { role: 'user', content: user }],
        { temperature: 0.2, top_p: 0.9, max_tokens: 300 }
      );
      const parsed = parseJsonLoose(text);
      return json({
        likelyVuln: parsed.likelyVuln === true,
        severity: sanitizeSeverity(parsed.severity),
        reason: typeof parsed.reason === 'string' ? parsed.reason : '',
        model,
      });
    }

    if (mode === 'report') {
      const user =
        `Evidence:\n${clampText(body.evidence)}\n\n` +
        `Draft the report JSON from ONLY this evidence now.`;
      const text = await groqChat(
        model,
        [{ role: 'system', content: REPORT_SYSTEM }, { role: 'user', content: user }],
        { temperature: 0.4, top_p: 0.9, max_tokens: 700 }
      );
      const parsed = parseJsonLoose(text);
      return json({
        summary: typeof parsed.summary === 'string' ? parsed.summary : '',
        steps: Array.isArray(parsed.steps) ? parsed.steps.map((s) => String(s)).slice(0, 20) : [],
        impact: typeof parsed.impact === 'string' ? parsed.impact : '',
        remediation: typeof parsed.remediation === 'string' ? parsed.remediation : '',
        model,
      });
    }

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
