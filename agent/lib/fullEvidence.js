'use strict';
// Full PoC evidence: route a tool's traffic through mitmdump and capture the real
// request/response flows. Heavily fallback-safe — if mitmdump is missing or the
// proxy fails, the tool runs normally and evidence degrades to Light (never throws,
// never blocks the scan). DI'd (spawnImpl/binExists/runCommand) for testing.
const { spawn } = require('child_process');
const { mkdtempSync, readFileSync, rmSync } = require('fs');
const os = require('os');
const path = require('path');

async function runWithFullEvidence({
  def,
  cmd,
  runCommand,
  binExists,
  port = Number(process.env.AGENT_PROXY_PORT || 18080),
  capAddon = process.env.AGENT_MITM_ADDON || '/opt/iris/capture.py',
  spawnImpl = spawn,
  settleMs = 1500,
} = {}) {
  const base = def && def.timeoutMs ? { timeoutMs: def.timeoutMs } : undefined;
  if (!binExists('mitmdump')) {
    const result = await runCommand(cmd, base);
    return { result, evidence: { mode: 'light', reason: 'mitmdump_unavailable' } };
  }
  const dir = mkdtempSync(path.join(os.tmpdir(), 'iris-flows-'));
  const flowFile = path.join(dir, 'flows.jsonl');
  let proxy;
  try {
    proxy = spawnImpl('mitmdump', ['-q', '--listen-port', String(port), '-s', capAddon, '--set', `iris_out=${flowFile}`], { stdio: 'ignore' });
    await new Promise((r) => setTimeout(r, settleMs));
    const env = {
      HTTP_PROXY: `http://127.0.0.1:${port}`, HTTPS_PROXY: `http://127.0.0.1:${port}`,
      http_proxy: `http://127.0.0.1:${port}`, https_proxy: `http://127.0.0.1:${port}`,
    };
    const result = await runCommand(cmd, { timeoutMs: def && def.timeoutMs, env });
    let flows = [];
    try {
      flows = readFileSync(flowFile, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)).slice(0, 20);
    } catch (_) { /* no flows */ }
    return { result, evidence: { mode: flows.length ? 'full' : 'light', flows } };
  } catch (_) {
    const result = await runCommand(cmd, base);
    return { result, evidence: { mode: 'light', reason: 'proxy_error' } };
  } finally {
    try { proxy && proxy.kill('SIGKILL'); } catch (_) {}
    try { rmSync(dir, { recursive: true, force: true }); } catch (_) {}
  }
}

module.exports = { runWithFullEvidence };
