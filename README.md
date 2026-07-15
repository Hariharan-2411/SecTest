# Iris — Web Security Testing Toolkit (Chrome MV3)

A Chrome/Brave extension for safe, repeatable web-app security testing and a
**personal bug-bounty cockpit**. You drive it in the browser; it does the boring
80% (recon → scan → triage prep) behind hard guardrails, and hands you ranked,
confidence-scored candidates. **You own the creative 20% and the submit button —
nothing is ever auto-submitted.**

![MV3](https://img.shields.io/badge/chrome-MV3-yellow.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)

> ⚠️ **Authorized testing only.** Use exclusively on assets you have written
> permission to test. Unauthorized testing may violate the CFAA, the Computer
> Misuse Act, and similar laws. See [Safety](#-safety--guardrails).

---

## What it does

- **Scans forms** — enumerates every input/textarea/select/file field and runs
  OWASP-family payloads (XSS · SQLi · Command Injection · Path Traversal · SSRF ·
  XPath · LDAP) across compatible fields. Never auto-submits.
- **Scans the surfaces forms miss** — passively inventories **REST/JSON**
  endpoints, probes **GraphQL** (introspection/schema/suggestions), and observes
  **WebSocket** handshakes + frames as you browse. See
  [Scan surfaces](#scan-surfaces-rest--graphql--websocket).
- **Passive recon while you browse** — endpoints, params, tech, storage-key
  *names* (never values), security-header misconfigs, secrets in JS, DOM-XSS
  sink/taint candidates, and JS-file diffing so a new endpoint raises an alert.
- **Scores every finding** — a deterministic **validation gate** assigns 0–100
  confidence so noise stays out of reports; **enrichment** adds CWE + CVSS;
  **chains** proposes multi-step exploits (validated against real findings).
- **Runs terminal recon** via an optional loopback **Companion Agent**
  (`subfinder`/`httpx`/`nmap`/`nuclei`/…) — scope-gated, the browser can't.
- **Auto-Triage recon agent** — an LLM plans in-scope enumeration; safe tools run
  automatically, active tools pause for your approval, and you get a ranked triage
  draft.
- **Drafts reports** in H1/Bugcrowd markdown — gated on confidence — for you to
  verify and submit.

For the full file-by-file map see **[FILES.md](FILES.md)**; for the design
rationale and roadmap see **[BUG_BOUNTY_AUTOMATION_PLAN.md](BUG_BOUNTY_AUTOMATION_PLAN.md)**
and the specs in [`docs/superpowers/specs/`](docs/superpowers/specs/).

---

## The popup, tab by tab

| Tab | What it does |
|---|---|
| **Scan** | Enumerate form fields; tick targets; drop a `[TEST_…]` marker as a reachability check. Text-like inputs are eligible; `date/number/range/color/file/select` are skipped. |
| **Payloads** | Run a vuln family across selected fields. Source = Library (benign) · File (`.txt`) · Text (your own) · AI. Sanctioned lab hosts bypass the dangerous-string filter. |
| **Recon** | Passive **Site Inventory**; **API Surface** / **API Tests** / **GraphQL** / **WebSocket** cards; **Security Headers**; **JS Change Monitor**; **Companion Agent** controls; and the **Auto-Triage** recon agent. |
| **Findings** | Every finding scored `confidence% · band`, with a min-confidence filter and one-click report drafting. |
| **Checklist** | Structured methodology checklist to cover a target systematically. |
| **Programs** | Track each program's in/out-of-scope assets + payouts. Source of truth for scope sync. |
| **AI** | Generate context-aware payloads/analysis via **Groq** (cloud, via a proxy — see below). |
| **History** | Every payload you've run, re-appliable. |
| **Settings** | All guardrails: host allowlist, Dry Run, audit log, rate limit, program scope, Companion Agent URL/token, AI model. |

### Scan surfaces (REST · GraphQL · WebSocket)

The scanner reaches past `<form>` fields. Passive discovery is always safe; every
active probe inherits the same guardrails and all findings flow through the same
validation gate → enrichment → report pipeline.

- **REST / API** — inventories XHR/fetch endpoints as you browse (routes
  templated, so `/users/123` and `/users/456` collapse to one). A gated probe
  pulls the full endpoint map from an exposed OpenAPI/Swagger doc (a readable spec
  is itself a finding). **API Tests** run **GET-only** candidate checks: reflected
  injection, missing-auth replay, and IDOR tagging — access-control results are
  *candidates for you to verify*, never confirmed bugs.
- **GraphQL** — a benign, read-only introspection probe (never a mutation):
  introspection-enabled is an instant finding plus the full query/mutation/type
  surface; also catches field-suggestion schema leaks and query batching.
- **WebSocket** — passive handshake analysis flags **CSWSH** candidates
  (cookie-authed socket with no per-connection token), and a MAIN-world shim shows
  live frames. Observe-only — frames are never altered or replayed.

---

## Companion Agent

The browser can't run `nmap`/`nuclei`. The [Companion Agent](agent/README.md) is a
zero-dependency, **loopback-only** service that runs allow-listed recon tools
against **in-scope** targets and returns results, re-checking scope on every call.

```bash
cd agent
cp .env.example .env          # set AGENT_TOKEN=$(openssl rand -hex 24)
docker compose up --build     # → http://127.0.0.1:8787
```

Then in the popup → **Settings / Recon → Companion Agent**: set URL + token →
**Check Health** → **Sync scope** → run tools from **Recon**.

| Tool | Risk | Purpose |
|------|------|---------|
| subfinder · dnsx · httpx | safe | subdomains, DNS, live-host probing |
| gau · waybackurls | safe | historical URLs (no target traffic) |
| naabu · nmap | active | port / service scan |
| nuclei | active | known-vuln template scan |
| katana · ffuf · feroxbuster | active | crawl / content brute-force |

`safe` = passive; `active` = touches the target, gated by scope **and** the
`AGENT_ALLOW_ACTIVE` switch. No shell (`execFile` with array args), token
required, bound to `127.0.0.1`, rate-limited.

---

## Install

**Prerequisites:** Node 16+ and npm; Chrome or Brave. Optional: Docker (for the
agent + lab targets).

```bash
cd chrome-boiler
npm install
npm run build          # → build/  (npm run start for watch mode)
```

Then in `chrome://extensions/` → enable **Developer mode** → **Load unpacked** →
select the `build/` directory.

**First run:** open the popup → Settings → add `localhost`/`127.0.0.1` to the host
allowlist → keep **Dry Run** on → Scan a page.

---

## AI (Groq via a proxy)

AI features (payload/finding drafting, escalation, the Auto-Triage planner) run on
**Groq**, called through a **Supabase Edge Function proxy** so the Groq API key
never ships in the extension. The proxy verifies the signed-in user's JWT.

- Function: [`supabase/functions/groq-proxy/`](supabase/functions/groq-proxy/) —
  deploy it and set your Groq key as a function secret.
- Client: `src/utils/aiProvider.js` — configure the model in the **AI** tab.

No local model is required; there is no Ollama dependency.

---

## Learn & practice

[`LEARN.html`](LEARN.html) is a self-contained tutorial + inert practice lab with
forms mapped to each vuln family.

```bash
python3 -m http.server 8000    # → http://localhost:8000/LEARN.html
```

For heavier targets, `test-targets.sh` spins up DVWA / WebGoat / Juice Shop via
Docker (`./test-targets.sh dvwa|webgoat|all|stop|status`).

---

## Safety & guardrails

**On by default:** Dry Run mode · host allowlist · confirmation dialogs · audit
logging (last 100 actions, exportable) · rate limiting (20/min) · payload
validation.

**Never automatic:** form submission · navigation · cookie/storage modification ·
report submission.

**Design guarantees:**

- **Scope is enforced server-side and centrally** — no tool fires against a host
  not on the active program's in-scope list; the Companion Agent re-checks too.
- **Confidence-gated** — findings below the report threshold are kept in a
  low-confidence view, never drafted; the LLM can *narrate* a score but never move
  it.
- **Human owns the verdict** — access-control / IDOR / DoS results are surfaced as
  *candidates* for human judgment; injection tests are **GET-only** (read-only);
  active tools require explicit approval. **No auto-submission, ever.**

---

## Architecture

```
Browser ── popup (React) ─────────── the cockpit: tabs, findings, triage
        └─ content script ────────── form scanner, passive observation, WS relay
        └─ MAIN-world shim ────────── WebSocket frame capture
        └─ service worker ─────────── guardrails, webRequest observers, active probes
                    │
                    ├── Groq proxy (Supabase Edge Fn) ─ AI, key server-side
                    └── Companion Agent (loopback) ──── nmap/nuclei/… scope-gated
                                    │
        GitHub Actions cron ────────┴─ continuous recon → diff → notify on deltas
```

Pure logic lives in `src/utils/` (unit-tested, no `chrome.*`/network); `src/pages/`
is thin browser glue. Every source produces one normalized **Finding** → validation
gate → enrichment → chains/report. See [FILES.md](FILES.md) for the full map.

---

## Development

```bash
npm run build      # production bundle
npm run start      # watch mode
npm test           # jest (pure-logic unit tests)
npm run prettier   # format
```

Contributions: pure logic is **test-first** — add a `tests/<module>.test.js` and
watch it fail before implementing. Keep `chrome.*`/network out of `src/utils/`.

---

## License

MIT — see [LICENSE](LICENSE). Provided "as is," no warranty. You are responsible
for obtaining authorization and complying with all applicable laws.
