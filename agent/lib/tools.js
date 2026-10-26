// Tool registry for the companion agent.
//
// Each tool declares a risk level (safe | active | destructive — §9.4/§9.5 of
// the plan) and a PURE arg-builder. Args are always passed to execFile as an
// ARRAY (never a shell string), so a target can never inject a command. Only
// allow-listed tools with fixed, non-destructive flag sets can run.
//
// SAFETY: `active` tools (port scans, nuclei, crawl/brute) are gated by
// ALLOW_ACTIVE + scope. `destructive` tools (injection scanners: dalfox, sqlmap)
// fire real payloads and are gated by a SEPARATE, default-OFF ALLOW_DESTRUCTIVE
// and by scope, and the orchestrator additionally requires explicit per-run human
// approval. Their flag sets are DETECTION-ONLY and bounded — no data exfiltration
// (no sqlmap --dump/--os-shell), so a confirmed hit is a non-destructive PoC.

'use strict';

const { spawn } = require('child_process');
const { hostFromTarget } = require('./scope');

// Bounded profiles keep scans light and program-friendly by default.
const PORT_PROFILES = { quick: '100', top1000: '1000' };

// Wordlist for content-discovery tools (ffuf/feroxbuster). Overridable via env;
// defaults to a path present in the Docker image / common on Kali.
const WORDLIST = process.env.AGENT_WORDLIST || '/usr/share/wordlists/dirb/common.txt';
// Phase 1: DNS brute wordlist + resolver list for puredns (bundled in the image).
const DNS_WORDLIST = process.env.AGENT_DNS_WORDLIST || '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt';
const RESOLVERS = process.env.AGENT_RESOLVERS || '/resolvers.txt';
// Confirmation tools (sqlmap/sstimap/commix) need minutes to CONFIRM, not 120s —
// bounded by this hard cap so a run can never hang.
const CONFIRM_TIMEOUT = Number(process.env.AGENT_CONFIRM_TIMEOUT_MS || 420000);

// Content-discovery crawl depth by profile (katana/feroxbuster stay shallow).
const CRAWL_DEPTH = { quick: '2', top1000: '2', deep: '3' };

/**
 * @type {Record<string, {risk:'safe'|'active'|'destructive', bin:string, build:(host:string, target:string, profile:string)=>string[]}>}
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
    build: (host, url) => ['-silent', '-json', '-status-code', '-title', '-tech-detect', '-u', url],
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
    build: (host, url, profile) => [
      '-silent',
      '-jsonl',
      '-jc',          // crawl endpoints referenced inside JS bundles — SPAs keep
                      // their API routes (/rest, /api) there, not in static HTML
      '-kf', 'all',   // known files: robots.txt, sitemap.xml
      '-d', CRAWL_DEPTH[profile] || CRAWL_DEPTH.quick,
      '-c', '10',
      '-timeout', '10',
      '-u', url,
    ],
  },
  ffuf: {
    risk: 'active',
    bin: 'ffuf',
    build: (host, url) => [
      '-w', WORDLIST,
      '-u', `${url}/FUZZ`,
      '-mc', '200,204,301,302,307,401,403',
      '-t', '40',
      '-rate', '50',
      '-s', // silent: emit results only
    ],
  },
  feroxbuster: {
    risk: 'active',
    bin: 'feroxbuster',
    build: (host, url) => [
      '-u', `${url}/`,
      '-w', WORDLIST,
      '-d', '1',
      '-t', '20',
      '--silent',
    ],
  },

  // --- injection scanners (DESTRUCTIVE: fire real payloads) ------------------
  // Gated by ALLOW_DESTRUCTIVE (default off) + scope, and the orchestrator asks
  // a human to approve each run. Flags are DETECTION-ONLY and bounded. They test
  // the target endpoint (scheme/port honored; path+query preserved for param
  // testing).
  dalfox: {
    // XSS. Reflection/DOM detection with PoC output; no stored-payload abuse.
    risk: 'destructive',
    bin: 'dalfox',
    build: (host, url) => [
      'url', url,
      '--silence',
      '--no-color',
      '--no-spinner',
      '--format', 'json',
      '--skip-bav',          // skip basic-auth brute / noisy checks
      '--worker', '20',
      '--timeout', '10',
    ],
  },
  sqlmap: {
    // SQLi DETECTION only: low level/risk, boolean+time techniques, NEVER --dump,
    // --os-shell, --tamper, or file read/write. A hit proves injectability without
    // exfiltrating data (non-destructive PoC per the plan's guardrails §8).
    risk: 'destructive',
    bin: 'sqlmap',
    timeoutMs: CONFIRM_TIMEOUT,
    build: (host, url) => [
      '-u', url,
      '--batch',             // non-interactive
      '--level=2',
      '--risk=1',
      '--technique=BEU',     // boolean + error + UNION detection (no stacked writes)
      '--flush-session',
      '--disable-coloring',
    ],
  },

  // ===================== Phase 1 — expanded coverage =====================
  // --- safe ---
  assetfinder: {
    risk: 'safe',
    bin: 'assetfinder',
    build: (host) => ['--subs-only', host],
  },
  wafw00f: {
    risk: 'safe',
    bin: 'wafw00f',
    build: (host, url) => [url, '-a', '-o', '-', '-f', 'json'],
  },
  cvemap: {
    // Enrichment, not a host scanner (queries a CVE DB). Registered so it ships +
    // shows in /health; loop integration (feed tech/nuclei → CVEs) is a follow-up.
    risk: 'safe',
    bin: 'cvemap',
    build: () => ['-silent', '-json', '-limit', '50'],
  },
  trufflehog: {
    // Secrets. Content-mode: the server fetches in-scope content to a temp dir,
    // then runs this over the dir (not a host-target tool).
    risk: 'safe',
    bin: 'trufflehog',
    mode: 'content',
    buildContent: (dir) => ['filesystem', dir, '--json', '--no-update'],
  },
  gitleaks: {
    risk: 'safe',
    bin: 'gitleaks',
    mode: 'content',
    buildContent: (dir) => ['detect', '--source', dir, '--no-git', '-f', 'json', '--report-path', '/dev/stdout'],
  },

  // --- active (scope + approval gated) ---
  amass: {
    risk: 'active',
    bin: 'amass',
    build: (host) => ['enum', '-passive', '-d', host, '-silent'],
  },
  puredns: {
    risk: 'active',
    bin: 'puredns',
    build: (host) => ['bruteforce', DNS_WORDLIST, host, '-r', RESOLVERS, '--quiet'],
  },
  arjun: {
    risk: 'active',
    bin: 'arjun',
    build: (host, url) => ['-u', url, '-oJ', '/dev/stdout', '-q'],
  },
  subzy: {
    risk: 'active',
    bin: 'subzy',
    build: (host, url) => ['run', '--target', url, '--hide_fails'],
  },
  s3scanner: {
    risk: 'active',
    bin: 's3scanner',
    build: (host) => ['scan', '--bucket', host],
  },
  crlfuzz: {
    risk: 'active',
    bin: 'crlfuzz',
    build: (host, url) => ['-u', url, '-s'],
  },
  jwt_tool: {
    risk: 'active',
    bin: 'jwt_tool',
    build: (host, url) => [url, '-M', 'at'],
  },
  wpscan: {
    risk: 'active',
    bin: 'wpscan',
    build: (host, url) => {
      const a = ['--url', url, '--format', 'json', '--no-banner', '--random-user-agent'];
      if (process.env.WPSCAN_API_TOKEN) a.push('--api-token', process.env.WPSCAN_API_TOKEN);
      return a;
    },
  },
  gowitness: {
    risk: 'active',
    bin: 'gowitness',
    build: (host, url) => ['scan', 'single', '--url', url, '--screenshot-path', '/tmp/iris-shots'],
  },

  // --- destructive (detection-only, bounded; gated by ALLOW_DESTRUCTIVE + approval) ---
  sstimap: {
    // SSTI detection. No --os-shell / eval-exec; just confirm injectability.
    risk: 'destructive',
    bin: 'sstimap',
    timeoutMs: CONFIRM_TIMEOUT,
    build: (host, url) => ['-u', url, '--batch'],
  },
  commix: {
    // Command-injection DETECTION only: default techniques, NEVER --os-shell/
    // --os-cmd/--os-pwn/--file-write/--file-read.
    risk: 'destructive',
    bin: 'commix',
    timeoutMs: CONFIRM_TIMEOUT,
    build: (host, url) => ['-u', url, '--batch', '--level=1'],
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
/**
 * Normalize a raw target into a base endpoint URL for URL-based tools. Honors an
 * explicit scheme + port; defaults to https when no scheme is given; preserves a
 * `:port` and path/query (useful for param-level injection testing). Scope is
 * still enforced on the bare host (hostFromTarget), never on this URL.
 */
function targetEndpoint(input) {
  const host = hostFromTarget(input);
  if (!host) return '';
  const s = String(input).trim();
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
    try {
      const u = new URL(s);
      const path = u.pathname === '/' ? '' : u.pathname;
      return `${u.protocol}//${u.host}${path}${u.search}`;
    } catch (_) { /* fall through */ }
  }
  const portMatch = s.split('/')[0].match(/:(\d+)$/);
  return `https://${host}${portMatch ? ':' + portMatch[1] : ''}`;
}

// Apply a per-engagement requests/sec cap to the tools that support it, so a
// program's "limit requests per second" rule can be honored. Tools with a native
// req/s flag get it set; the injection tools get an inter-request --delay instead.
// rate <= 0 (or unset) → leave the tool's bounded defaults untouched.
const RATE_FLAG = { nuclei: '-rate-limit', ffuf: '-rate', httpx: '-rl', katana: '-rl' };
function applyRate(args, tool, rate) {
  const r = Number(rate);
  if (!(r > 0)) return args;
  const flag = RATE_FLAG[tool];
  if (flag) {
    const i = args.indexOf(flag);
    if (i >= 0 && i + 1 < args.length) { args[i + 1] = String(r); return args; }
    return args.concat([flag, String(r)]);
  }
  if (tool === 'sqlmap') return args.concat(['--delay', (1 / r).toFixed(2)]);        // seconds between requests
  if (tool === 'dalfox') return args.concat(['--delay', String(Math.max(1, Math.round(1000 / r)))]); // ms between requests
  return args;
}

function buildCommand(tool, target, profile = 'quick', opts = {}) {
  const def = TOOLS[tool];
  if (!def) throw new Error(`unknown_tool:${tool}`);
  if (def.mode === 'content') throw new Error('content_tool'); // runs via fetch-then-scan, not here
  const host = hostFromTarget(target);
  if (!host) throw new Error('bad_target');
  const url = targetEndpoint(target);
  // Domain-based tools (subfinder/dnsx) and port scanners (naabu/nmap) ignore the
  // URL and use `host`; URL-based tools use the normalized endpoint.
  const args = applyRate(def.build(host, url, profile), tool, opts.rate);
  return { bin: def.bin, args, risk: def.risk, host };
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
function runCommand({ bin, args }, { timeoutMs = 120000, maxBuffer = 8 * 1024 * 1024, env } = {}) {
  return new Promise((resolve) => {
    let out = '';
    let err = '';
    let killed = false;
    let child;
    try {
      child = spawn(bin, args, {
        stdio: ['ignore', 'pipe', 'pipe'],
        env: env ? { ...process.env, ...env } : process.env,
      });
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

module.exports = { TOOLS, listTools, buildCommand, runCommand, targetEndpoint, PORT_PROFILES };
