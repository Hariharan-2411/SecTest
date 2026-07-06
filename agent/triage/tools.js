// Triage-agent tools — the bridge between Claude and the companion agent.
//
// The LLM (runner.js) plans recon by calling these tools; each one is a thin,
// READ-THROUGH call to the local companion agent's HTTP API. Scope is enforced
// SERVER-SIDE by the companion agent, so the model literally cannot scan a host
// that isn't in scope — an out-of-scope attempt comes back as a tool error the
// model must respect. Nothing here exploits or submits anything.

'use strict';

// System prompt: the triage methodology + hard guardrails. Pure string.
const SYSTEM_PROMPT = `You are a bug-bounty RECON & TRIAGE assistant. You help an authorized
security researcher plan reconnaissance against IN-SCOPE targets and produce a ranked,
human-reviewable triage report. You run tools through a scope-gated local agent.

Your job:
1. Use "list_tools" to see what recon tools are available and "get_scope" to confirm scope.
2. Plan recon for the target: enumerate subdomains, probe live hosts, fingerprint tech,
   map ports, and run known-vuln templates — using the safe tools first (subfinder, dnsx,
   httpx), then active tools (naabu, nmap, nuclei) only as the target warrants.
3. Read each tool's results, decide the next step, and build a picture of the attack surface.
4. Produce a RANKED TRIAGE REPORT: the most promising leads first, each with what was
   observed, why it's interesting, and the concrete next manual step for the human.

Hard rules — non-negotiable:
- ONLY act on in-scope targets. If a scan returns "out_of_scope", stop and report it — never
  try to work around scope.
- You do RECON and TRIAGE only. You do NOT exploit, you do NOT exfiltrate data, you do NOT
  submit anything. Your output is a DRAFT for a human to verify.
- IDOR, access-control, business-logic, and impact judgments are the HUMAN's call. You may
  flag candidates ("this endpoint uses sequential IDs — worth an IDOR check") but you cannot
  confirm them.
- Be honest: report what the tools actually returned. Don't invent findings or inflate severity.
- End every report with an explicit reminder that the human must validate and decide whether
  to submit.`;

// Tool definitions (raw JSON Schema — the Messages API tool-use format).
const TOOL_DEFS = [
  {
    name: 'list_tools',
    description: 'List the recon tools the companion agent can run, with their risk level and whether the binary is installed. Also reports whether active tools are enabled.',
    input_schema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'get_scope',
    description: 'Return the companion agent\'s current in-scope / out-of-scope host patterns. Confirm scope before planning scans.',
    input_schema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'recon_scan',
    description: 'Run one recon tool against an in-scope target via the companion agent. Scope is re-checked server-side; an out-of-scope target is rejected. Returns parsed, structured results (subdomains / http / ports / findings).',
    input_schema: {
      type: 'object',
      properties: {
        tool: { type: 'string', enum: ['subfinder', 'dnsx', 'httpx', 'naabu', 'nmap', 'nuclei'], description: 'Which tool to run.' },
        target: { type: 'string', description: 'The in-scope host or domain (e.g. example.com or app.example.com).' },
        profile: { type: 'string', enum: ['quick', 'top1000', 'services'], description: 'Scan depth. quick = light/top-100; top1000 = broader; services = nmap service detection.' },
      },
      required: ['tool', 'target'],
      additionalProperties: false,
    },
  },
];

/**
 * Pure: validate + normalize a recon_scan tool call into an agent /scan body.
 * Throws on an unknown tool or empty target. Keeps the agent request well-formed
 * regardless of what the model emits.
 */
const VALID_TOOLS = ['subfinder', 'dnsx', 'httpx', 'naabu', 'nmap', 'nuclei'];
const VALID_PROFILES = ['quick', 'top1000', 'services'];
function planScanRequest(input = {}) {
  const tool = String(input.tool || '').trim();
  const target = String(input.target || '').trim();
  if (!VALID_TOOLS.includes(tool)) throw new Error(`unknown_tool:${tool}`);
  if (!target) throw new Error('missing_target');
  const profile = VALID_PROFILES.includes(input.profile) ? input.profile : 'quick';
  return { tool, target, profile };
}

/**
 * Build an executor bound to a companion-agent config { url, token }.
 * Returns async executeTool(name, input) → parsed JSON (or { error }).
 */
function makeExecutor({ url = 'http://127.0.0.1:8787', token = '' } = {}) {
  const base = url.replace(/\/$/, '');
  const call = async (path, opts = {}) => {
    try {
      const res = await fetch(base + path, {
        method: opts.method || 'GET',
        headers: { 'Content-Type': 'application/json', 'x-agent-token': token },
        body: opts.body ? JSON.stringify(opts.body) : undefined,
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) return { error: (data && data.error) || `http_${res.status}`, ...data };
      return data;
    } catch (e) {
      return { error: 'agent_unreachable', detail: String((e && e.message) || e) };
    }
  };

  return async function executeTool(name, input) {
    switch (name) {
      case 'list_tools':
        return call('/health');
      case 'get_scope':
        return call('/scope');
      case 'recon_scan': {
        let body;
        try {
          body = planScanRequest(input);
        } catch (e) {
          return { error: String((e && e.message) || e) };
        }
        return call('/scan', { method: 'POST', body });
      }
      default:
        return { error: `unknown_tool_call:${name}` };
    }
  };
}

module.exports = { SYSTEM_PROMPT, TOOL_DEFS, planScanRequest, makeExecutor, VALID_TOOLS, VALID_PROFILES };
