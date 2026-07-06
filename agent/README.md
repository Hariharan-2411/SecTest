# Companion Agent (Phase 3)

A tiny, **zero-dependency** HTTP service that runs allow-listed recon tools
against **in-scope** targets and hands the results back to the Chrome extension.
The browser is sandboxed and can't run `nmap`/`subfinder`/etc. — this agent is
how the extension reaches the terminal.

> **Authorization first.** Only ever point this at assets you are explicitly
> authorized to test. The agent re-checks scope on every request, but *you* are
> responsible for what's in scope.

## What it runs

| Tool | Risk | Purpose |
|------|------|---------|
| subfinder | safe | subdomain enumeration |
| dnsx | safe | DNS resolution |
| httpx | safe | live-host probing, titles, tech |
| gau | safe | historical URLs from archives (no target traffic) |
| waybackurls | safe | historical URLs from the Wayback Machine |
| naabu | active | port scan (top ports) |
| nmap | active | port/service detail |
| nuclei | active | known-vuln template scan |
| katana | active | crawl the live host for endpoints |
| ffuf | active | content/directory brute-force |
| feroxbuster | active | recursive content discovery |

`safe` = passive/read-only (archive queries never touch the target). `active` =
touches the target (port scans, crawls, brute-force, template requests) — gated
by scope **and** the `AGENT_ALLOW_ACTIVE` switch. **No destructive tools are
included**, by design (plan §9.4/§9.5).

Content-discovery brute-forcers read a wordlist from `AGENT_WORDLIST` (defaults to
`/usr/share/wordlists/dirb/common.txt`). Profiles: `quick`/`top1000` (depth 2),
`deep` (crawl depth 3, katana).

## Run it (Docker, recommended — Apple Silicon native)

```bash
cd agent
cp .env.example .env
# edit .env: set AGENT_TOKEN to a long random string (openssl rand -hex 24)
docker compose up --build
```

The agent is now on **http://127.0.0.1:8787** (host-loopback only — not exposed
to your network). First `nuclei` run uses templates baked into the image.

## Run it (native, no Docker)

Requires Node ≥18 and the tools on your `PATH` (via Homebrew / `go install`):

```bash
AGENT_TOKEN=$(openssl rand -hex 24) node server.js
# it prints the token if you don't set one
```

## Connect the extension

1. Open the extension → **Config → Companion Agent**.
2. Set **Agent URL** = `http://127.0.0.1:8787` and paste your **AGENT_TOKEN**.
3. Click **Check Health** — you should see the tool list.
4. Click **Sync scope** to push the extension's program scope to the agent.
5. Run tools from **Recon → Companion Agent**.

## API

| Method | Route | Auth | Body / Notes |
|--------|-------|------|--------------|
| GET | `/health` | none | tool availability + scope sizes + `oob` flag |
| GET | `/scope` | token | current scope |
| PUT | `/scope` | token | `{ inScope: string[], outOfScope: string[] }` |
| POST | `/scan` | token | `{ tool, target, profile }` — target re-checked against scope |
| POST | `/oob/new` | token | mint a callback URL → `{ cid, url }` (OOB enabled only) |
| GET | `/oob/poll?cid=` | token | interactions recorded for a cid (OOB enabled only) |

Auth is the `x-agent-token` header. `/scan` returns `403 out_of_scope` for any
target not in scope, `403 active_disabled` if active tools are off, `429` when
rate-limited, `501 tool_not_installed` if the binary is missing.

## Guardrails

- **Scope enforced server-side** on every `/scan` — the agent never trusts the
  client (same model as the extension: out-of-scope always wins).
- **No shell.** Tools run via `execFile` with array args, so a target string
  can't inject flags or commands.
- **Token required** for everything except `/health`.
- **Bound to loopback** (`127.0.0.1`) — not reachable from the network.
- **Rate-limited** (`AGENT_RATE_MAX`/min).
- **Active tools switchable off** with `AGENT_ALLOW_ACTIVE=false`.

## Out-of-band (OOB) confirmation

Blind bugs (blind SSRF, blind RCE) produce no visible response. The OOB catcher
confirms them: mint a unique callback URL, embed it in a payload, and if the
target's backend fetches it, the interaction is recorded — proof that input
reached a network sink.

Enable it (off by default; also needs active tools on):

```bash
AGENT_OOB_ENABLE=true AGENT_ALLOW_ACTIVE=true node server.js
```

```bash
# 1. mint a callback URL
curl -s -XPOST -H "x-agent-token: $TOKEN" http://127.0.0.1:8787/oob/new
#    → { "cid": "ab12…", "url": "http://127.0.0.1:8788/ab12…" }

# 2. put that url in a payload (e.g. an SSRF field), then poll:
curl -s -H "x-agent-token: $TOKEN" "http://127.0.0.1:8787/oob/poll?cid=ab12…"
#    → { "interactions": [ { "ts", "method", "path", "remote", … } ] }
```

**HTTP-only and LISTEN-only** — it runs no DNS listener and never sends. By
default it binds to `127.0.0.1`, so only same-host callbacks are caught. Catching
callbacks from an external target requires binding wider (`AGENT_OOB_BIND=0.0.0.0`)
and pointing `AGENT_OOB_HOST` at a reachable address — that exposes a listener, so
do it only deliberately and within your authorized engagement.

## Test

```bash
node --test        # pure-logic tests (scope, arg-building, parsing, oob)
```
