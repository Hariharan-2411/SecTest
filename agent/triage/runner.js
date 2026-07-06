// Triage agent — the "brain". Plans recon against an IN-SCOPE target by calling
// the companion agent's tools, then produces a ranked, human-reviewable triage
// report. Runs on the host (your Mac); the tools run in the Docker companion
// agent. Scope is enforced server-side, so the model cannot scan out of scope.
//
//   Usage:  node runner.js <in-scope-target>   [e.g. node runner.js example.com]
//   Env:    ANTHROPIC_API_KEY (or an `ant auth login` profile)
//           AGENT_URL   (default http://127.0.0.1:8787)
//           AGENT_TOKEN (the companion agent token, from agent/.env)
//
// This produces a DRAFT. A human validates findings and decides whether to submit.

'use strict';

const Anthropic = require('@anthropic-ai/sdk');
const { SYSTEM_PROMPT, TOOL_DEFS, makeExecutor } = require('./tools');

const MODEL = process.env.TRIAGE_MODEL || 'claude-opus-4-8';
const MAX_ITERATIONS = Number(process.env.TRIAGE_MAX_ITERATIONS || 25);
const MAX_TOOL_RESULT_CHARS = 40000; // keep tool results from ballooning the context

async function main() {
  const target = process.argv[2];
  if (!target) {
    console.error('Usage: node runner.js <in-scope-target>');
    process.exit(1);
  }

  const client = new Anthropic(); // resolves key from env or `ant auth login` profile
  const executeTool = makeExecutor({
    url: process.env.AGENT_URL || 'http://127.0.0.1:8787',
    token: process.env.AGENT_TOKEN || '',
  });

  const messages = [
    {
      role: 'user',
      content:
        `Plan reconnaissance and produce a ranked triage report for the in-scope target: ${target}\n\n` +
        `First confirm scope and available tools, then run recon, then rank what a human should look at first.`,
    },
  ];

  for (let i = 0; i < MAX_ITERATIONS; i++) {
    let response;
    try {
      response = await client.messages.create({
        model: MODEL,
        max_tokens: 16000,
        thinking: { type: 'adaptive' },
        system: SYSTEM_PROMPT,
        tools: TOOL_DEFS,
        messages,
      });
    } catch (e) {
      console.error('\n[Anthropic API error]', (e && e.message) || e);
      process.exit(1);
    }

    // Surface any assistant text as it arrives (thinking is summarized/omitted).
    for (const block of response.content) {
      if (block.type === 'text' && block.text.trim()) {
        process.stdout.write('\n' + block.text.trim() + '\n');
      }
    }

    // Always append the FULL assistant content (incl. thinking + tool_use blocks).
    messages.push({ role: 'assistant', content: response.content });

    if (response.stop_reason === 'refusal') {
      console.error('\n[Model refused this request] — check that the target and task are legitimate authorized testing.');
      process.exit(1);
    }
    if (response.stop_reason === 'end_turn') {
      break; // final report printed above
    }
    if (response.stop_reason === 'pause_turn') {
      continue; // server-side pause — resend to resume
    }
    if (response.stop_reason === 'tool_use') {
      const toolResults = [];
      for (const block of response.content) {
        if (block.type !== 'tool_use') continue;
        process.stderr.write(`  → ${block.name}(${JSON.stringify(block.input)})\n`);
        const out = await executeTool(block.name, block.input);
        toolResults.push({
          type: 'tool_result',
          tool_use_id: block.id,
          content: JSON.stringify(out).slice(0, MAX_TOOL_RESULT_CHARS),
          is_error: Boolean(out && out.error),
        });
      }
      messages.push({ role: 'user', content: toolResults });
      continue;
    }
    // Any other stop reason (e.g. max_tokens): stop cleanly.
    console.error(`\n[Stopped: ${response.stop_reason}]`);
    break;
  }

  console.log('\n\n─────────────────────────────────────────────');
  console.log('DRAFT ONLY — verify every finding and its impact yourself.');
  console.log('The agent does not decide to submit. You do.');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
