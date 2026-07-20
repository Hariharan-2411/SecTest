// Adaptive payload feedback loop (B3) — pure orchestration, DI-testable.
//
// Turns payload generation from a one-shot into a guided search: Groq proposes a
// payload grounded in the observed surface (B1), a deterministic OBSERVER runs it
// on a canary/marker and reports whether it succeeded (reflection/oracle/domProbe
// = the fitness function), and the result is fed back so Groq refines/evades on
// the next round. The LLM is the mutation strategist; the code decides success.
// Bounded by MAX_ROUNDS. Both `chat` and `observe` are injected — no network here.
// Never throws.

export const MAX_ROUNDS = 4;

function clip(v, max = 200) {
  const s = typeof v === 'string' ? v : v == null ? '' : String(v);
  return s.replace(/\s+/g, ' ').trim().slice(0, max);
}

/** Extract the payload from a `[PAYLOAD] … [EXPLANATION] …` reply. Pure. */
export function parsePayloadReply(text) {
  if (typeof text !== 'string') return '';
  const m = text.match(/\[PAYLOAD\]([\s\S]*?)(?:\[EXPLANATION\]|$)/i);
  return m ? m[1].trim() : '';
}

/** Build the (single user) prompt for round N, grounding + prior failed attempts. */
export function buildRefinePrompt(vuln, context = {}, history = []) {
  const vulnLabel = typeof vuln === 'string' ? vuln : (vuln && (vuln.label || vuln.key)) || 'the target vulnerability';
  const ground = [];
  if (context.framework) ground.push(`Framework: ${context.framework}`);
  if (context.reflectionContext) ground.push(`Reflection context (where input lands): ${context.reflectionContext}`);
  if (context.sink) ground.push(`DOM sink: ${context.sink}`);

  let content =
    `You are an authorized penetration tester crafting a ${vulnLabel} payload for a lab target with explicit permission.\n`;
  if (ground.length) content += ground.join('\n') + '\n';
  const seedFirst = (!Array.isArray(history) || !history.length) && Array.isArray(context.priorWins) && context.priorWins.length;
  if (seedFirst) {
    content += '\nPayloads that worked before on similar targets (adapt or reuse if apt):\n';
    for (const p of context.priorWins.slice(0, 5)) content += `- ${clip(p)}\n`;
  }
  if (Array.isArray(history) && history.length) {
    content += '\nPrior attempts (each FAILED — refine: vary encoding/breakout and evade the observed filtering):\n';
    for (const h of history.slice(-MAX_ROUNDS)) {
      content += `- payload: ${clip(h && h.payload)} → result: ${clip(h && h.observation && h.observation.evidence) || 'no success'}\n`;
    }
  }
  content += '\nReturn ONE payload in exactly this format: [PAYLOAD] <raw payload> [EXPLANATION] <one sentence>.';
  return [{ role: 'user', content }];
}

/**
 * Run the adaptive loop. Impure via injected `chat` (LLM) and `observe` (runs the
 * payload, returns { success, evidence }). Never throws.
 * @returns {Promise<{success:boolean, payload:string, rounds:number, history:object[]}>}
 */
export async function adaptivePayloadLoop({ vuln, context, chat, observe, model } = {}, { maxRounds = MAX_ROUNDS } = {}) {
  const history = [];
  for (let round = 0; round < maxRounds; round++) {
    let payload = '';
    try {
      const messages = buildRefinePrompt(vuln, context, history);
      const replyText = await chat(messages, model);
      payload = parsePayloadReply(replyText);
    } catch (_) {
      break; // LLM failure ends the loop
    }
    if (!payload) break;

    let observation;
    try {
      observation = await observe(payload);
    } catch (_) {
      observation = { success: false, evidence: 'observer error' };
    }
    history.push({ payload, observation });
    if (observation && observation.success) {
      return { success: true, payload, rounds: round + 1, history };
    }
  }
  return {
    success: false,
    payload: history.length ? history[history.length - 1].payload : '',
    rounds: history.length,
    history,
  };
}
