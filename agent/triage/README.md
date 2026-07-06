# Triage Agent (Phase 5) — the Claude "brain"

A Claude-powered agent that **plans recon and drafts a ranked triage report** by
driving the scope-gated companion agent. It's the orchestrator/brain from the
plan (§6): the LLM decides *which tool to run next* and *what a human should look
at first* — the actual tools run in the Docker companion agent, and **scope is
enforced there server-side**, so the model cannot scan out of scope.

> It produces a **draft**. IDOR / access-control / business-logic bugs and the
> decision to submit are the human's — the agent flags candidates, never confirms
> or submits them.

## How it fits

```
You ──▶ triage agent (host, this folder)      ──HTTP──▶  companion agent (Docker)  ──▶ nmap/subfinder/…
        Claude opus-4-8 plans recon & ranks             scope re-checked server-side
```

The agent uses the Claude Messages API with tool use (a manual agentic loop). Its
three tools are read-through calls to the companion agent: `list_tools`,
`get_scope`, `recon_scan`.

## Setup

Requires Node ≥ 18 and a running companion agent (see ../README.md).

```bash
cd agent/triage
npm install                      # installs @anthropic-ai/sdk

# Auth: either an API key…
export ANTHROPIC_API_KEY=sk-ant-...
#   …or `ant auth login` (the SDK picks up the profile automatically)

# Point at your companion agent + token (from agent/.env):
export AGENT_URL=http://127.0.0.1:8787
export AGENT_TOKEN=<your AGENT_TOKEN>

# Run against an IN-SCOPE, authorized target:
node runner.js example.com
```

The agent streams its plan and tool calls, then prints a ranked triage report.

## Configuration

| Env | Default | Purpose |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | Claude auth (or use `ant auth login`) |
| `AGENT_URL` | `http://127.0.0.1:8787` | companion agent base URL |
| `AGENT_TOKEN` | — | companion agent token |
| `TRIAGE_MODEL` | `claude-opus-4-8` | model id |
| `TRIAGE_MAX_ITERATIONS` | `25` | max agent-loop turns |

## Guardrails

- **Scope is the companion agent's job** — the LLM can request any target, but the
  agent rejects out-of-scope ones (`403 out_of_scope`), which the model must respect.
- **Recon & triage only** — the system prompt forbids exploitation, exfiltration,
  and submission. No destructive tools exist in the companion agent anyway.
- **Human-in-the-loop** — output ends with a "verify and decide to submit yourself"
  reminder; the agent never submits.

## Test

```bash
node --test        # pure-logic tests (tool schemas, scan planning, guardrails)
```
