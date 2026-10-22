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

// Mask a secret so only its shape is stored, never the live value.
function maskSecret(s) {
  s = String(s || '');
  return s.length <= 8 ? '***' : `${s.slice(0, 3)}***${s.slice(-2)}`;
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
    case 'dalfox': {
      // dalfox --format json emits a JSON array (or JSONL) of PoC objects.
      let pocs = [];
      try {
        const j = JSON.parse(raw);
        pocs = Array.isArray(j) ? j : [j];
      } catch (_) {
        pocs = parseJsonl(stdout);
      }
      const items = pocs
        .filter((p) => p && (p.data || p.evidence || p.poc || p.type))
        .map((p) => ({
          templateId: 'dalfox-xss',
          name: `XSS (${p.type || p.inject_type || 'reflected'})`,
          severity: 'high',
          matched: p.data || p.poc || p.evidence || '',
        }));
      return { kind: 'findings', items, count: items.length, raw };
    }
    case 'sqlmap': {
      // Detection-only: surface a finding iff sqlmap reports injectability.
      const text = String(stdout || '');
      const vulnerable =
        /is vulnerable/i.test(text) ||
        /sqlmap identified the following injection point/i.test(text) ||
        /Parameter:.*\n.*Type:/i.test(text);
      const params = Array.from(text.matchAll(/Parameter:\s*(.+)/gi)).map((m) => m[1].trim());
      const items = vulnerable
        ? [{
            templateId: 'sqlmap-sqli',
            name: 'SQL injection (detected, not exploited)',
            severity: 'high',
            matched: params.length ? `params: ${params.join(', ')}` : 'injectable parameter',
          }]
        : [];
      return { kind: 'findings', items, count: items.length, raw };
    }
    case 'gau':
    case 'waybackurls':
    case 'ffuf':
    case 'feroxbuster': {
      // All emit one URL/path per line; dedupe.
      const items = Array.from(new Set(nonEmptyLines(stdout)));
      return { kind: 'urls', items, count: items.length, raw };
    }
    // ===================== Phase 1 — expanded coverage =====================
    case 'assetfinder':
    case 'amass':
    case 'puredns': {
      const items = Array.from(new Set(nonEmptyLines(stdout)));
      return { kind: 'subdomains', items, count: items.length, raw };
    }
    case 'wafw00f': {
      let items = [];
      try { const j = JSON.parse(raw); items = Array.isArray(j) ? j : [j]; } catch (_) { /* non-json */ }
      return { kind: 'info', items, count: items.length, raw };
    }
    case 'cvemap': {
      const items = parseJsonl(stdout).map((c) => ({
        templateId: c.cve_id || c.id || 'cve',
        name: String(c.cve_description || c.name || '').slice(0, 120),
        severity: c.severity || 'info',
        matched: c.cve_id || '',
      }));
      return { kind: 'findings', items, count: items.length, raw };
    }
    case 'arjun': {
      let params = [];
      try { params = Object.values(JSON.parse(raw)).flat(); } catch (_) { /* non-json */ }
      const items = Array.from(new Set(params));
      return { kind: 'urls', items, count: items.length, raw };
    }
    case 'subzy': {
      const items = nonEmptyLines(stdout)
        .filter((l) => /vulnerable/i.test(l))
        .map((l) => ({ templateId: 'subzy-takeover', name: 'Subdomain takeover', severity: 'high', matched: l, type: 'takeover' }));
      return { kind: 'findings', items, count: items.length, raw };
    }
    case 's3scanner': {
      const items = nonEmptyLines(stdout)
        .filter((l) => /open|public|AuthenticatedUsers|AllUsers|exists/i.test(l))
        .map((l) => ({ templateId: 's3-exposure', name: 'Exposed S3 bucket', severity: 'medium', matched: l, type: 's3-exposure' }));
      return { kind: 'findings', items, count: items.length, raw };
    }
    case 'crlfuzz': {
      const items = nonEmptyLines(stdout)
        .filter((l) => /^https?:\/\//i.test(l) || /vuln/i.test(l))
        .map((l) => ({ templateId: 'crlf', name: 'CRLF injection', severity: 'medium', matched: l, type: 'crlf' }));
      return { kind: 'findings', items, count: items.length, raw };
    }
    case 'jwt_tool': {
      const vuln = /vulnerab|weak key|cracked|None algorithm|accepted/i.test(raw);
      const items = vuln ? [{ templateId: 'jwt', name: 'JWT weakness', severity: 'high', matched: 'jwt_tool flagged a weakness', type: 'jwt' }] : [];
      return { kind: 'findings', items, count: items.length, raw };
    }
    case 'wpscan': {
      const vulns = [];
      try {
        const j = JSON.parse(raw);
        const collect = (o) => { if (o && Array.isArray(o.vulnerabilities)) vulns.push(...o.vulnerabilities); };
        collect(j.main_theme);
        for (const k of ['plugins', 'themes']) if (j[k]) for (const n of Object.keys(j[k])) collect(j[k][n]);
        if (Array.isArray(j.interesting_findings)) for (const f of j.interesting_findings) vulns.push({ title: f.to_s || f.url });
      } catch (_) { /* non-json */ }
      const items = vulns.map((v) => ({ templateId: 'wpscan', name: v.title || 'WordPress issue', severity: 'medium', matched: v.references ? JSON.stringify(v.references) : '', type: 'wordpress' }));
      return { kind: 'findings', items, count: items.length, raw };
    }
    case 'gowitness': {
      const items = [{ templateId: 'screenshot', name: 'Screenshot captured', severity: 'info', matched: '/tmp/iris-shots', type: 'screenshot' }];
      return { kind: 'findings', items, count: items.length, raw };
    }
    case 'sstimap': {
      const vuln = /is vulnerable|injection identified|Engine:|template injection/i.test(raw);
      const items = vuln ? [{ templateId: 'ssti', name: 'Server-side template injection (detected)', severity: 'high', matched: 'sstimap confirmed injectability', type: 'ssti' }] : [];
      return { kind: 'findings', items, count: items.length, raw };
    }
    case 'commix': {
      const vuln = /is vulnerable|injection point|appears to be injectable/i.test(raw);
      const items = vuln ? [{ templateId: 'cmd-injection', name: 'Command injection (detected)', severity: 'critical', matched: 'commix confirmed injectability', type: 'cmd-injection' }] : [];
      return { kind: 'findings', items, count: items.length, raw };
    }
    case 'trufflehog': {
      const items = parseJsonl(stdout)
        .filter((r) => r && (r.Raw || r.Redacted || r.DetectorName))
        .map((r) => ({ templateId: 'secret', name: `secret (${r.DetectorName || 'generic'})`, severity: 'high', matched: maskSecret(r.Redacted || r.Raw || ''), type: 'secrets' }));
      return { kind: 'findings', items, count: items.length, raw };
    }
    case 'gitleaks': {
      let rows = [];
      try { const j = JSON.parse(raw); rows = Array.isArray(j) ? j : []; } catch (_) { rows = parseJsonl(stdout); }
      const items = rows.map((r) => ({ templateId: 'secret', name: `secret (${r.RuleID || r.Description || 'rule'})`, severity: 'high', matched: maskSecret(r.Secret || r.Match || ''), type: 'secrets' }));
      return { kind: 'findings', items, count: items.length, raw };
    }

    default:
      return { kind: 'raw', items: nonEmptyLines(stdout), count: 0, raw };
  }
}

module.exports = { parseOutput, nonEmptyLines, parseJsonl };
