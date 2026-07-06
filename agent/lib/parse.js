// Normalize each tool's raw stdout into a compact, structured shape the
// extension can render and fold into its inventory. Pure — no I/O.

'use strict';

function nonEmptyLines(stdout, cap = 2000) {
  return String(stdout || '')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean)
    .slice(0, cap);
}

function parseJsonl(stdout, cap = 1000) {
  const out = [];
  for (const line of nonEmptyLines(stdout, cap)) {
    try {
      out.push(JSON.parse(line));
    } catch (_) {
      /* skip non-JSON lines (banners, etc.) */
    }
  }
  return out;
}

/**
 * @returns {{kind:string, items:Array, count:number, raw:string}}
 */
function parseOutput(tool, stdout) {
  const raw = String(stdout || '').slice(0, 20000);

  switch (tool) {
    case 'subfinder': {
      const items = nonEmptyLines(stdout);
      return { kind: 'subdomains', items, count: items.length, raw };
    }
    case 'dnsx': {
      const items = nonEmptyLines(stdout);
      return { kind: 'dns', items, count: items.length, raw };
    }
    case 'httpx': {
      const items = parseJsonl(stdout).map((r) => ({
        url: r.url || r.input || '',
        status: r.status_code || r.status || null,
        title: r.title || '',
        tech: r.tech || r.technologies || [],
      }));
      return { kind: 'http', items, count: items.length, raw };
    }
    case 'naabu': {
      // lines look like "host:port"
      const items = nonEmptyLines(stdout).map((l) => {
        const i = l.lastIndexOf(':');
        return { host: i >= 0 ? l.slice(0, i) : l, port: i >= 0 ? l.slice(i + 1) : '' };
      });
      return { kind: 'ports', items, count: items.length, raw };
    }
    case 'nmap': {
      // Extract "PORT STATE SERVICE" open lines; keep raw for the full report.
      const items = nonEmptyLines(stdout)
        .filter((l) => /^\d+\/(tcp|udp)\s+open/i.test(l))
        .map((l) => {
          const [portproto, state, ...svc] = l.split(/\s+/);
          return { port: portproto, state, service: svc.join(' ') };
        });
      return { kind: 'ports', items, count: items.length, raw };
    }
    case 'nuclei': {
      const items = parseJsonl(stdout).map((f) => ({
        templateId: f['template-id'] || f.templateID || '',
        name: (f.info && f.info.name) || '',
        severity: (f.info && f.info.severity) || 'info',
        matched: f['matched-at'] || f.host || '',
      }));
      return { kind: 'findings', items, count: items.length, raw };
    }
    case 'katana': {
      // katana -jsonl emits one object per URL; endpoint field varies by version.
      const urls = parseJsonl(stdout)
        .map((j) => j.endpoint || (j.request && j.request.endpoint) || j.url || '')
        .filter(Boolean);
      const items = Array.from(new Set(urls));
      return { kind: 'urls', items, count: items.length, raw };
    }
    case 'gau':
    case 'waybackurls':
    case 'ffuf':
    case 'feroxbuster': {
      // All emit one URL/path per line; dedupe.
      const items = Array.from(new Set(nonEmptyLines(stdout)));
      return { kind: 'urls', items, count: items.length, raw };
    }
    default:
      return { kind: 'raw', items: nonEmptyLines(stdout), count: 0, raw };
  }
}

module.exports = { parseOutput, nonEmptyLines, parseJsonl };
