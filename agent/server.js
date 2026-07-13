// Companion agent — a small, zero-dependency HTTP service that runs allow-listed
// recon tools against IN-SCOPE targets only. The Chrome extension talks to it
// over localhost. It re-checks scope server-side on every scan (never trusts the
// client), requires a shared token, rate-limits, and refuses destructive work.
//
// Run: AGENT_TOKEN=... node server.js   (or via Docker — see README.md)

'use strict';

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { parseScopeText, evaluateTarget } = require('./lib/scope');
const { listTools, buildCommand, runCommand, TOOLS } = require('./lib/tools');
const { parseOutput } = require('./lib/parse');
const { createWatch, isDue, recordRun, summarizeWatch } = require('./lib/watches');
const { loadWatches, saveWatches } = require('./lib/store');
const { formatWatchTitle, formatWatchBody, buildWebhookPayload } = require('./lib/notify');
const { OobCatcher } = require('./lib/oob');

const PORT = Number(process.env.AGENT_PORT || 8787);
const ALLOW_ACTIVE = process.env.AGENT_ALLOW_ACTIVE !== 'false'; // active tools on by default

// --- out-of-band interaction catcher (opt-in; confirms blind bugs) -----------
const OOB_ENABLE = process.env.AGENT_OOB_ENABLE === 'true';
const OOB_PORT = Number(process.env.AGENT_OOB_PORT || 8788);
const OOB_BIND = process.env.AGENT_OOB_BIND || '127.0.0.1'; // safe default: same-host only
const OOB_HOST = process.env.AGENT_OOB_HOST || `127.0.0.1:${OOB_PORT}`; // what payloads point at
let oob = null;
// Token: from env, else generate one and print it (the extension needs it).
const TOKEN = process.env.AGENT_TOKEN || crypto.randomBytes(24).toString('hex');
if (!process.env.AGENT_TOKEN) {
  console.log('\n  No AGENT_TOKEN set — generated one for this run:\n');
  console.log('    ' + TOKEN + '\n');
  console.log('  Paste it into the extension (Config → Companion Agent).\n');
}

// Mutable scope, seeded from env, updatable via PUT /scope from the extension.
let scope = {
  inScope: parseScopeText(process.env.AGENT_SCOPE_IN || ''),
  outOfScope: parseScopeText(process.env.AGENT_SCOPE_OUT || ''),
};

// --- simple in-memory rate limiter (agent is long-lived, unlike the SW) ------
const RATE_MAX = Number(process.env.AGENT_RATE_MAX || 30); // scans/min
let scanTimes = [];
function rateOk() {
  const cutoff = Date.now() - 60000;
  scanTimes = scanTimes.filter((t) => t > cutoff);
  if (scanTimes.length >= RATE_MAX) return false;
  scanTimes.push(Date.now());
  return true;
}

// Optional outbound webhook for delta alerts (Discord/Slack/Telegram).
const WEBHOOK_URL = process.env.AGENT_WEBHOOK_URL || '';
const WEBHOOK_PLATFORM = process.env.AGENT_WEBHOOK_PLATFORM || 'discord';

// --- orchestration: watches + jobs + scheduler (Phase 4) ---------------------
// Which parse `kind` each tool produces maps to which recon-diff category.
const KIND_TO_CATEGORY = {
  subdomains: 'subdomains',
  dns: 'dns',
  http: 'http',
  ports: 'ports',
  findings: 'findings',
  urls: 'urls',
};

let watches = loadWatches(); // [{...watch}]
const jobs = new Map(); // jobId -> { id, watchId, status, startedAt, finishedAt, result, error }

// Serialize all tool execution so scheduled + manual runs never overlap (rate
// limits + resource safety). Each unit of work is a function returning a promise.
let queueTail = Promise.resolve();
function enqueue(fn) {
  const run = queueTail.then(fn, fn);
  queueTail = run.catch(() => {});
  return run;
}

function persistWatches() {
  try {
    saveWatches(watches);
  } catch (e) {
    console.error('saveWatches failed:', e && e.message);
  }
}

async function sendWebhook(title, body) {
  if (!WEBHOOK_URL) return;
  try {
    const payload = buildWebhookPayload(WEBHOOK_PLATFORM, title, body);
    await fetch(WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  } catch (e) {
    console.error('webhook failed:', e && e.message);
  }
}

// Run every tool in a watch against its target, aggregate into one snapshot.
async function buildSnapshot(watch) {
  const snapshot = { subdomains: [], dns: [], http: [], ports: [], findings: [], urls: [] };
  for (const tool of watch.tools) {
    const def = TOOLS[tool];
    if (!def) continue;
    if (def.risk === 'active' && !ALLOW_ACTIVE) continue;
    // Re-check scope for every tool run — never trust stored state blindly.
    if (!evaluateTarget(watch.target, scope).allowed) continue;
    if (!binExists(def.bin)) continue;
    if (!rateOk()) continue;
    let cmd;
    try {
      cmd = buildCommand(tool, watch.target, watch.profile || 'quick');
    } catch (_) {
      continue;
    }
    const result = await runCommand(cmd);
    const parsed = parseOutput(tool, result.stdout);
    const cat = KIND_TO_CATEGORY[parsed.kind];
    if (cat) snapshot[cat] = snapshot[cat].concat(parsed.items || []);
  }
  return snapshot;
}

// Execute one watch: build snapshot, diff, persist, notify on new surface.
function runWatchJob(watchId) {
  const jobId = 'j_' + crypto.randomBytes(6).toString('hex');
  jobs.set(jobId, { id: jobId, watchId, status: 'queued', createdAt: new Date().toISOString() });

  enqueue(async () => {
    const idx = watches.findIndex((w) => w.id === watchId);
    if (idx < 0) {
      jobs.set(jobId, { ...jobs.get(jobId), status: 'error', error: 'watch_not_found' });
      return;
    }
    jobs.set(jobId, { ...jobs.get(jobId), status: 'running', startedAt: new Date().toISOString() });
    const target = { ...watches[idx], running: true };
    watches[idx] = target;
    persistWatches();
    try {
      const snapshot = await buildSnapshot(target);
      // Re-resolve by id — the watch may have been DELETED during the (long)
      // tool run. A stale index would otherwise resurrect a ghost entry.
      const cur = watches.findIndex((w) => w.id === watchId);
      if (cur < 0) {
        jobs.set(jobId, { ...jobs.get(jobId), status: 'done', finishedAt: new Date().toISOString(), result: { deletedDuringRun: true } });
        return;
      }
      const { watch: updated, delta, interesting } = recordRun(watches[cur], snapshot);
      watches[cur] = updated;
      persistWatches();
      if (interesting) {
        const title = formatWatchTitle(updated.target, delta.addedTotal);
        await sendWebhook(title, formatWatchBody(updated.target, delta));
      }
      jobs.set(jobId, {
        ...jobs.get(jobId),
        status: 'done',
        finishedAt: new Date().toISOString(),
        result: { interesting, addedTotal: delta.addedTotal, counts: delta.counts },
      });
    } catch (e) {
      const cur = watches.findIndex((w) => w.id === watchId);
      if (cur >= 0) {
        watches[cur] = { ...watches[cur], running: false };
        persistWatches();
      }
      jobs.set(jobId, { ...jobs.get(jobId), status: 'error', error: String((e && e.message) || e) });
    }
  });

  return jobId;
}

// Scheduler: every minute, enqueue any due watch. The serial queue prevents
// overlap; scope + rate limits still apply inside buildSnapshot.
const SCHED_MS = Number(process.env.AGENT_SCHED_MS || 60000);
function schedulerTick() {
  const now = Date.now();
  for (const w of watches) {
    if (isDue(w, now)) runWatchJob(w.id);
  }
}

// --- tool availability (scan PATH for the binary) ----------------------------
function binExists(bin) {
  const dirs = (process.env.PATH || '').split(path.delimiter);
  return dirs.some((d) => {
    try {
      return fs.existsSync(path.join(d, bin));
    } catch (_) {
      return false;
    }
  });
}

// --- tiny response helpers ---------------------------------------------------
function send(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'content-type, x-agent-token',
    'Access-Control-Allow-Methods': 'GET, PUT, POST, OPTIONS',
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', (c) => {
      data += c;
      if (data.length > 1e6) req.destroy(); // 1MB guard
    });
    req.on('end', () => {
      try {
        resolve(data ? JSON.parse(data) : {});
      } catch (_) {
        resolve(null);
      }
    });
    req.on('error', () => resolve(null));
  });
}

function authed(req) {
  return (req.headers['x-agent-token'] || '') === TOKEN;
}

// --- routes ------------------------------------------------------------------
async function handle(req, res) {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const route = url.pathname;

  if (req.method === 'OPTIONS') return send(res, 204, {});

  // /health is unauthenticated so the extension can probe reachability, but it
  // reveals nothing sensitive beyond tool availability.
  if (route === '/health' && req.method === 'GET') {
    return send(res, 200, {
      ok: true,
      version: 1,
      allowActive: ALLOW_ACTIVE,
      oob: !!oob,
      tools: listTools().map((t) => ({ ...t, available: binExists(TOOLS[t.name].bin) })),
      scope: { inScope: scope.inScope.length, outOfScope: scope.outOfScope.length },
    });
  }

  // Everything below requires the token.
  if (!authed(req)) return send(res, 401, { error: 'unauthorized' });

  if (route === '/scope' && req.method === 'GET') {
    return send(res, 200, scope);
  }

  // --- out-of-band interaction endpoints ------------------------------------
  // Mint a callback URL to embed in a payload, then poll for hits. A recorded
  // interaction confirms the target's backend reached out — i.e. a blind bug.
  if (route === '/oob/new' && req.method === 'POST') {
    if (!oob) return send(res, 501, { error: 'oob_disabled' });
    const cid = oob.mint();
    return send(res, 200, { ok: true, cid, url: `http://${OOB_HOST}/${cid}`, host: OOB_HOST });
  }
  if (route === '/oob/poll' && req.method === 'GET') {
    if (!oob) return send(res, 501, { error: 'oob_disabled' });
    const cid = url.searchParams.get('cid') || '';
    return send(res, 200, { ok: true, cid, interactions: oob.poll(cid) });
  }

  if (route === '/scope' && req.method === 'PUT') {
    const body = await readBody(req);
    if (!body || !Array.isArray(body.inScope)) return send(res, 400, { error: 'bad_scope' });
    scope = {
      inScope: body.inScope.map(String),
      outOfScope: Array.isArray(body.outOfScope) ? body.outOfScope.map(String) : [],
    };
    return send(res, 200, { ok: true, scope });
  }

  if (route === '/scan' && req.method === 'POST') {
    const body = await readBody(req);
    if (!body || !body.tool || !body.target) return send(res, 400, { error: 'missing_tool_or_target' });

    const def = TOOLS[body.tool];
    if (!def) return send(res, 400, { error: 'unknown_tool' });
    if (def.risk === 'active' && !ALLOW_ACTIVE) return send(res, 403, { error: 'active_disabled' });

    // The gate: target must be in scope, checked HERE, server-side.
    const ev = evaluateTarget(body.target, scope);
    if (!ev.allowed) return send(res, 403, { error: ev.reason, host: ev.host });

    if (!binExists(def.bin)) return send(res, 501, { error: 'tool_not_installed', tool: body.tool });
    if (!rateOk()) return send(res, 429, { error: 'rate_limited' });

    let cmd;
    try {
      cmd = buildCommand(body.tool, body.target, body.profile);
    } catch (e) {
      return send(res, 400, { error: String(e.message || e) });
    }

    const started = Date.now();
    const result = await runCommand(cmd);
    const parsed = parseOutput(body.tool, result.stdout);
    return send(res, 200, {
      ok: result.ok,
      tool: body.tool,
      risk: cmd.risk,
      host: ev.host,
      command: `${cmd.bin} ${cmd.args.join(' ')}`,
      durationMs: Date.now() - started,
      timedOut: result.timedOut,
      exitCode: result.code,
      ...parsed,
    });
  }

  // --- watches (scheduled recon) --------------------------------------------
  if (route === '/watches' && req.method === 'GET') {
    return send(res, 200, { watches: watches.map(summarizeWatch) });
  }

  if (route === '/watches' && req.method === 'POST') {
    const body = await readBody(req);
    if (!body || !body.target) return send(res, 400, { error: 'missing_target' });
    // A watch can only target something in scope — checked here.
    const ev = evaluateTarget(body.target, scope);
    if (!ev.allowed) return send(res, 403, { error: ev.reason, host: ev.host });
    // Validate requested tools exist + are permitted.
    const tools = (Array.isArray(body.tools) ? body.tools : []).filter((t) => TOOLS[t]);
    if (tools.some((t) => TOOLS[t].risk === 'active' && !ALLOW_ACTIVE)) {
      return send(res, 403, { error: 'active_disabled' });
    }
    const watch = createWatch({ target: body.target, tools: tools.length ? tools : undefined, intervalMinutes: body.intervalMinutes });
    if (body.profile) watch.profile = body.profile;
    watches.push(watch);
    persistWatches();
    return send(res, 200, { ok: true, watch: summarizeWatch(watch) });
  }

  const watchMatch = route.match(/^\/watch\/([\w]+)(\/run)?$/);
  if (watchMatch) {
    const id = watchMatch[1];
    const idx = watches.findIndex((w) => w.id === id);
    if (idx < 0) return send(res, 404, { error: 'watch_not_found' });

    if (watchMatch[2] === '/run' && req.method === 'POST') {
      const jobId = runWatchJob(id);
      return send(res, 202, { ok: true, jobId });
    }
    if (req.method === 'GET') {
      // Full watch incl. history (trim lastSnapshot to keep the payload small).
      const w = watches[idx];
      return send(res, 200, { ...w, lastSnapshot: undefined });
    }
    if (req.method === 'DELETE') {
      watches.splice(idx, 1);
      persistWatches();
      return send(res, 200, { ok: true });
    }
  }

  const jobMatch = route.match(/^\/jobs\/([\w]+)$/);
  if (jobMatch && req.method === 'GET') {
    const job = jobs.get(jobMatch[1]);
    if (!job) return send(res, 404, { error: 'job_not_found' });
    return send(res, 200, job);
  }

  return send(res, 404, { error: 'not_found' });
}

const server = http.createServer((req, res) => {
  handle(req, res).catch((e) => send(res, 500, { error: String((e && e.message) || e) }));
});

// Bind to localhost only by default — do not expose the agent to the network.
const HOST = process.env.AGENT_BIND || '127.0.0.1';
server.listen(PORT, HOST, () => {
  console.log(`Companion agent listening on http://${HOST}:${PORT}  (active tools: ${ALLOW_ACTIVE ? 'on' : 'off'})`);
  console.log(`  watches loaded: ${watches.length}${WEBHOOK_URL ? ' · webhook: on' : ''}`);
  // OOB catcher: opt-in AND requires active tools to be enabled.
  if (OOB_ENABLE && ALLOW_ACTIVE) {
    oob = new OobCatcher();
    oob.start({ port: OOB_PORT, host: OOB_BIND }).then(() => {
      console.log(`  OOB catcher: http://${OOB_BIND}:${OOB_PORT} (payload host: ${OOB_HOST})`);
      if (OOB_BIND !== '127.0.0.1') console.log('  ⚠️  OOB bound beyond loopback — reachable off-host. Ensure this is intended.');
    }).catch((e) => console.error('OOB start failed:', e && e.message));
  }
  // Start the scheduler once the server is up.
  setInterval(schedulerTick, SCHED_MS);
});

module.exports = { handle, server };
