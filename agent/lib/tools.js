// Tool registry for the companion agent.
//
// Each tool declares a risk level (safe | active | destructive — §9.4/§9.5 of
// the plan) and a PURE arg-builder. Args are always passed to execFile as an
// ARRAY (never a shell string), so a target can never inject a command. Only
// allow-listed tools with fixed, non-destructive flag sets can run.
//
// SAFETY: no destructive tools are registered. `active` tools (port scans,
// nuclei) are gated by ALLOW_ACTIVE in the server and by scope. Nothing here
// exploits — it enumerates and fingerprints only.

'use strict';

const { spawn } = require('child_process');
const { hostFromTarget } = require('./scope');

// Bounded profiles keep scans light and program-friendly by default.
const PORT_PROFILES = { quick: '100', top1000: '1000' };

// Wordlist for content-discovery tools (ffuf/feroxbuster). Overridable via env;
// defaults to a path present in the Docker image / common on Kali.
const WORDLIST = process.env.AGENT_WORDLIST || '/usr/share/wordlists/dirb/common.txt';

// Content-discovery crawl depth by profile (katana/feroxbuster stay shallow).
const CRAWL_DEPTH = { quick: '2', top1000: '2', deep: '3' };

/**
 * @type {Record<string, {risk:'safe'|'active', bin:string, build:(host:string, target:string, profile:string)=>string[]}>}
 */
const TOOLS = {
  subfinder: {
    risk: 'safe',
    bin: 'subfinder',
    build: (host) => ['-silent', '-d', host],
  },
  dnsx: {
    risk: 'safe',
    bin: 'dnsx',
    build: (host) => ['-silent', '-a', '-resp', '-d', host],
  },
  httpx: {
    risk: 'safe',
    bin: 'httpx',
    build: (host) => ['-silent', '-json', '-status-code', '-title', '-tech-detect', '-u', host],
  },
  naabu: {
    risk: 'active',
    bin: 'naabu',
    build: (host, target, profile) => [
      '-silent',
      '-host',
      host,
      '-top-ports',
      PORT_PROFILES[profile] || PORT_PROFILES.quick,
    ],
  },
  nmap: {
    risk: 'active',
    bin: 'nmap',
    build: (host, target, profile) => {
      // Non-intrusive by default: no aggressive timing, -Pn to skip host discovery.
      const ports = profile === 'top1000' ? '--top-ports=1000' : '--top-ports=100';
      const base = ['-Pn', '-T3', ports];
      if (profile === 'services') base.push('-sV', '--version-light');
      base.push(host);
      return base;
    },
  },
  nuclei: {
    risk: 'active',
    bin: 'nuclei',
    build: (host, target) => [
      '-silent',
      '-jsonl',
      '-severity',
      'low,medium,high,critical',
      '-rate-limit',
      '50',
      '-u',
      target,
    ],
  },

  // --- content discovery -----------------------------------------------------
  // gau / waybackurls query third-party archives (OTX, Wayback, CommonCrawl) —
  // they never touch the target, so they're 'safe'. katana / ffuf / feroxbuster
  // crawl or brute-force the live host, so they're 'active' (scope + ALLOW_ACTIVE
  // gated). All flag sets are fixed and bounded; the host is the only variable.
  gau: {
    risk: 'safe',
    bin: 'gau',
    build: (host) => ['--threads', '5', host],
  },
  waybackurls: {
    risk: 'safe',
    bin: 'waybackurls',
    build: (host) => [host],
  },
  katana: {
    risk: 'active',
    bin: 'katana',
    build: (host, target, profile) => [
      '-silent',
      '-jsonl',
      '-d', CRAWL_DEPTH[profile] || CRAWL_DEPTH.quick,
      '-c', '10',
      '-timeout', '10',
      '-u', `https://${host}`,
    ],
  },
  ffuf: {
    risk: 'active',
    bin: 'ffuf',
    build: (host) => [
      '-w', WORDLIST,
      '-u', `https://${host}/FUZZ`,
      '-mc', '200,204,301,302,307,401,403',
      '-t', '40',
      '-rate', '50',
      '-s', // silent: emit results only
    ],
  },
  feroxbuster: {
    risk: 'active',
    bin: 'feroxbuster',
    build: (host) => [
      '-u', `https://${host}/`,
      '-w', WORDLIST,
      '-d', '1',
      '-t', '20',
      '--silent',
    ],
  },
};

/** List registered tools with their risk levels. */
function listTools() {
  return Object.keys(TOOLS).map((name) => ({ name, risk: TOOLS[name].risk }));
}

/**
 * Build the execFile spec for a tool. Pure — throws on unknown tool.
 * @returns {{bin:string, args:string[], risk:string, host:string}}
 */
function buildCommand(tool, target, profile = 'quick') {
  const def = TOOLS[tool];
  if (!def) throw new Error(`unknown_tool:${tool}`);
  const host = hostFromTarget(target);
  if (!host) throw new Error('bad_target');
  return { bin: def.bin, args: def.build(host, host, profile), risk: def.risk, host };
}

/**
 * Run a built command via spawn (no shell). Returns stdout/stderr/code.
 *
 * IMPORTANT: stdin is 'ignore' (/dev/null). ProjectDiscovery tools (httpx,
 * dnsx, …) check stdin for piped targets and will BLOCK forever on an open,
 * empty stdin pipe even when a single target is passed via `-u`/`-d`. Ignoring
 * stdin gives them an immediate EOF so they proceed with the flag args.
 * Bounded by timeout + maxBuffer so a runaway tool can't hang or OOM the agent.
 */
function runCommand({ bin, args }, { timeoutMs = 120000, maxBuffer = 8 * 1024 * 1024 } = {}) {
  return new Promise((resolve) => {
    let out = '';
    let err = '';
    let killed = false;
    let child;
    try {
      child = spawn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (e) {
      return resolve({ ok: false, code: 1, timedOut: false, stdout: '', stderr: String(e && e.message) });
    }
    const timer = setTimeout(() => {
      killed = true;
      try { child.kill('SIGKILL'); } catch (_) {}
    }, timeoutMs);
    child.stdout.on('data', (d) => {
      if (out.length < maxBuffer) out += d.toString();
    });
    child.stderr.on('data', (d) => {
      if (err.length < 4000) err += d.toString();
    });
    child.on('error', (e) => {
      clearTimeout(timer);
      resolve({ ok: false, code: 1, timedOut: killed, stdout: '', stderr: String(e && e.message) });
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({
        ok: code === 0 || out.length > 0,
        code: typeof code === 'number' ? code : 1,
        timedOut: killed,
        stdout: out.slice(0, maxBuffer),
        stderr: err.slice(0, 4000),
      });
    });
  });
}

module.exports = { TOOLS, listTools, buildCommand, runCommand, PORT_PROFILES };
