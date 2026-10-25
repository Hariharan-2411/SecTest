// Evidence auto-capture + PoC scaffolding (I1) — pure, unit-testable.
//
// Turns a finding into a minimal, type-aware proof-of-concept scaffold for the
// report draft: reproduction steps, a repro command template, and the finding's
// own (capped) evidence. ETHOS: demonstrate impact with a canary / minimal PoC —
// never exfiltrate real user data. Pure; never throws.

function str(v, max = 500) {
  return typeof v === 'string' ? v.slice(0, max) : v == null ? '' : String(v).slice(0, max);
}
function clip(v, max = 500) {
  return str(v, max).replace(/\s+/g, ' ').trim();
}

function endpointOf(f) {
  if (f.target) return str(f.target, 300);
  if (f.endpoint) return str(f.endpoint, 300);
  const path = f.path || '';
  if (f.host) return `https://${f.host}${path}`;
  return str(path, 300);
}

const REPRO = {
  'api-injection': (f) => ({
    steps: [
      `Send a GET request to ${endpointOf(f) || 'the endpoint'} with a test payload on parameter "${f.param || '<param>'}".`,
      'Observe the payload reflected or acted on in the response.',
    ],
    repro: `curl -s '${endpointOf(f) || 'https://TARGET/PATH'}?${f.param || 'param'}=CANARY'`,
  }),
  'sqli-boolean': (f) => ({
    steps: [
      `Send the boolean-TRUE and boolean-FALSE variants of the payload to ${endpointOf(f) || 'the endpoint'}.`,
      'Confirm the response differs between the two (boolean-based SQL injection).',
    ],
    repro: `curl -s '${endpointOf(f) || 'https://TARGET/PATH'}?${f.param || 'id'}=1%20AND%201=1'   # compare to ...%20AND%201=2`,
  }),
  'dom-xss': (f) => ({
    steps: [
      `Place a unique canary into the source (${Array.isArray(f.sources) && f.sources.length ? f.sources.join(', ') : 'the identified source'}).`,
      `Confirm the canary reaches the sink "${f.sink || 'the DOM sink'}" unescaped and executes in the page.`,
    ],
    repro: '',
  }),
  'api-auth': (f) => ({
    steps: [
      `Replay the request to ${endpointOf(f) || 'the endpoint'} WITHOUT credentials (no cookie / token).`,
      'Observe a 2xx returning authenticated content — the endpoint is missing an authorization check.',
    ],
    repro: `curl -s -i '${endpointOf(f) || 'https://TARGET/PATH'}'   # send NO Authorization / Cookie header`,
  }),
  'api-idor-candidate': (f) => ({
    steps: [
      `Replay ${endpointOf(f) || 'the endpoint'} substituting another user's object id.`,
      "Confirm the response contains another user's data (verify it is genuinely another user's, not your own).",
    ],
    repro: `curl -s '${endpointOf(f) || 'https://TARGET/PATH/{id}'}'   # swap {id} for a neighbouring account's id`,
  }),
};

/** Build a minimal PoC scaffold from a finding. Pure; never throws. */
export function buildPocScaffold(finding) {
  const f = finding && typeof finding === 'object' ? finding : {};
  const type = str(f.type, 40) || 'finding';
  const target = f.host ? `https://${f.host}` : endpointOf(f);
  const gen = REPRO[type];
  const base = gen
    ? gen(f)
    : { steps: [`Reproduce the ${type} finding at ${target || 'the target'} using the evidence below.`], repro: '' };
  return {
    title: str(f.title, 200) || type,
    type,
    target,
    steps: base.steps,
    repro: base.repro || '',
    evidence: clip(f.evidence, 500), // minimal — never a full data dump
    minimalDataNote: 'Demonstrate impact with a canary or minimal PoC — never exfiltrate real user data.',
  };
}

/** Numbered steps (+ repro) as a plain string for the report draft's steps field. */
export function formatPocSteps(scaffold) {
  const s = scaffold || {};
  const out = [];
  (Array.isArray(s.steps) ? s.steps : []).forEach((st, i) => out.push(`${i + 1}. ${st}`));
  if (s.repro) out.push('', 'Repro:', s.repro);
  return out.join('\n');
}

/** Full markdown PoC block (for pasting into a report). */
export function formatPocMarkdown(scaffold) {
  const s = scaffold || {};
  const lines = [`### PoC — ${s.title || 'Finding'}`, ''];
  if (Array.isArray(s.steps) && s.steps.length) {
    lines.push('**Steps to reproduce:**');
    s.steps.forEach((st, i) => lines.push(`${i + 1}. ${st}`));
    lines.push('');
  }
  if (s.repro) lines.push('```', s.repro, '```', '');
  if (s.evidence) lines.push('**Evidence (minimal):**', '```', s.evidence, '```', '');
  lines.push(`> ${s.minimalDataNote || 'Use a minimal PoC — never exfiltrate real user data.'}`);
  return lines.join('\n');
}
