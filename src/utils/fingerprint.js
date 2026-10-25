// Tech fingerprint → targeted tool choice (#3). Pure, unit-testable.
//
// Reads what the loop has ALREADY observed (discovered URLs + findings) and
// derives per-host tech signals, each mapped to the dedicated tool that tests it.
// Fed into buildReconPrompt so the planner picks wpscan/subzy/jwt_tool/… on
// purpose instead of guessing from prose. Pure; never throws.

import { hostFromUrl } from './scope';

// Each signature matches a URL path and/or a finding type, and names the tool(s)
// that should run against it. Only tools that exist in RECON_TOOLS are referenced.
const SIGNATURES = [
  { tech: 'WordPress', tools: ['wpscan'], url: /\/wp-(login|admin|content|includes|json)|\/xmlrpc\.php/i, type: /wordpress|wp-/i },
  { tech: 'GraphQL', tools: ['nuclei'], note: 'graphql templates', url: /\/graphql|\/graphiql/i, type: /graphql/i },
  { tech: 'S3 bucket', tools: ['s3scanner'], url: /s3[.-][a-z0-9-]*\.amazonaws\.com|\.s3\./i, type: /\bs3\b|bucket/i },
  { tech: 'Exposed .git', tools: ['nuclei'], note: 'exposure templates', url: /\/\.git(\/|$)/i, type: /git-expos/i },
  { tech: 'JWT', tools: ['jwt_tool'], type: /jwt/i },
  { tech: 'Subdomain takeover', tools: ['subzy'], type: /takeover|dangling|cname/i },
];

const PARAM_URL = /\?[^=\s&]+=/;

function urlStrings(surface) {
  const raw = surface && Array.isArray(surface.urls) ? surface.urls : [];
  return raw.map((u) => (typeof u === 'string' ? u : u && (u.url || u.loc || u.endpoint))).filter((u) => typeof u === 'string');
}

/**
 * @param {{surface?:{urls?:any[]}, findings?:object[]}} context
 * @returns {{byHost:Object, suggestions:{tech:string,host:string,tools:string[],note?:string}[]}}
 */
export function fingerprintStack(context) {
  const ctx = context && typeof context === 'object' ? context : {};
  const urls = urlStrings(ctx.surface);
  const findings = Array.isArray(ctx.findings) ? ctx.findings : [];
  const byHost = {};
  const seen = new Set(); // dedupe by tech|host
  const suggestions = [];

  const add = (tech, host, tools, note) => {
    const key = `${tech}|${host || ''}`;
    if (seen.has(key)) return;
    seen.add(key);
    suggestions.push({ tech, host: host || '', tools, ...(note ? { note } : {}) });
    const h = host || '*';
    (byHost[h] = byHost[h] || { tech: [], tools: [] });
    if (!byHost[h].tech.includes(tech)) byHost[h].tech.push(tech);
    for (const t of tools) if (!byHost[h].tools.includes(t)) byHost[h].tools.push(t);
  };

  for (const sig of SIGNATURES) {
    if (sig.url) for (const u of urls) if (sig.url.test(u)) add(sig.tech, hostFromUrl(u), sig.tools, sig.note);
    if (sig.type) for (const f of findings) {
      const t = `${(f && (f.type || f.name || f.title)) || ''}`;
      if (sig.type.test(t)) add(sig.tech, f && (f.host || f.target), sig.tools, sig.note);
    }
  }
  // Parametered endpoints → injection tools (host-scoped).
  for (const u of urls) if (PARAM_URL.test(u)) add('Parametered endpoint', hostFromUrl(u), ['sqlmap', 'dalfox', 'arjun'], 'test the exact URL');

  return { byHost, suggestions };
}

/** One compact line for the planner prompt. Pure; never throws. */
export function formatFingerprint(fp) {
  const s = fp && Array.isArray(fp.suggestions) ? fp.suggestions : [];
  if (!s.length) return '';
  const parts = s.map((x) => `${x.tech}${x.host ? ` on ${x.host}` : ''} → ${x.tools.join('/')}${x.note ? ` (${x.note})` : ''}`);
  return `Detected tech → run the matching tool: ${parts.join('; ')}. `;
}
