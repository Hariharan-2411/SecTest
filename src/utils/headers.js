// Security-header & cookie analysis — pure, unit-testable (no chrome.*/network).
//
// Given the response headers of traffic the user ALREADY generated (captured
// passively via webRequest), flag common misconfigurations: missing/weak CSP,
// clickjacking exposure, permissive CORS, missing HSTS, MIME-sniffing, info-leak
// headers, and weak cookie attributes. Each finding is high-signal and
// low-false-positive — it reports header *facts*, never a guessed exploit.
//
// Purely analytical: it inspects headers you already received. It sends nothing.

// Severity words align with reportBuilder.SEVERITIES.
// `ref` uses CWE ids (precise, provider-neutral) for the report draft.

/** Build a case-insensitive header map: lower-name → value; set-cookie → array. */
function indexHeaders(headers) {
  const map = Object.create(null);
  const cookies = [];
  for (const h of Array.isArray(headers) ? headers : []) {
    if (!h || !h.name) continue;
    const name = String(h.name).toLowerCase();
    const value = h.value == null ? '' : String(h.value);
    if (name === 'set-cookie') {
      // A single set-cookie header value may contain multiple cookies split by
      // newlines when Chrome coalesces them.
      for (const line of value.split(/\n/)) {
        if (line.trim()) cookies.push(line.trim());
      }
    } else {
      map[name] = value;
    }
  }
  return { map, cookies };
}

function isHttps(url) {
  try {
    return new URL(url).protocol === 'https:';
  } catch (_) {
    return false;
  }
}

/** Parse one Set-Cookie line into { name, attrs:Set<lowercased-attr>, sameSite }. */
function parseCookie(line) {
  const parts = String(line).split(';').map((p) => p.trim());
  const name = (parts[0].split('=')[0] || '').trim();
  const attrs = new Set();
  let sameSite = '';
  for (let i = 1; i < parts.length; i++) {
    const [k, v] = parts[i].split('=');
    const key = (k || '').trim().toLowerCase();
    attrs.add(key);
    if (key === 'samesite') sameSite = (v || '').trim().toLowerCase();
  }
  return { name, attrs, sameSite };
}

/**
 * Analyze a captured response.
 * @param {{url:string, statusLine?:string, type?:string, headers:Array<{name,value}>}} resp
 * @returns {{id, severity, title, evidence, ref}[]}  (empty when clean)
 *
 * `type` is the webRequest resource type; framing/CSP checks only apply to
 * documents (main_frame / sub_frame), so API/XHR responses don't produce noise.
 */
export function analyzeHeaders(resp = {}) {
  const url = resp.url || '';
  const type = resp.type || 'main_frame';
  const isDocument = type === 'main_frame' || type === 'sub_frame';
  const https = isHttps(url);
  const { map, cookies } = indexHeaders(resp.headers);
  const out = [];
  const add = (id, severity, title, evidence, ref) =>
    out.push({ id, severity, title, evidence, ref });

  const csp = map['content-security-policy'];

  if (isDocument) {
    // 1. Content-Security-Policy.
    if (!csp) {
      add('missing-csp', 'medium', 'Missing Content-Security-Policy',
        'No Content-Security-Policy response header on a document response.', 'CWE-693');
    } else if (/(?:script-src|default-src)[^;]*'unsafe-inline'/i.test(csp)) {
      add('weak-csp', 'low', "CSP allows 'unsafe-inline' scripts",
        `Content-Security-Policy: ${csp.slice(0, 200)}`, 'CWE-693');
    }

    // 2. Clickjacking: no X-Frame-Options AND no CSP frame-ancestors.
    const xfo = map['x-frame-options'];
    const hasFrameAncestors = csp && /frame-ancestors/i.test(csp);
    if (!xfo && !hasFrameAncestors) {
      add('missing-frame-protection', 'medium', 'No clickjacking protection',
        'Neither X-Frame-Options nor CSP frame-ancestors is set.', 'CWE-1021');
    }
  }

  // 3. Permissive CORS: wildcard origin together with credentials.
  const acao = map['access-control-allow-origin'];
  const acac = map['access-control-allow-credentials'];
  if (acao === '*' && /true/i.test(acac || '')) {
    add('permissive-cors', 'high', 'Permissive CORS with credentials',
      'Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true.', 'CWE-942');
  }

  // 4. HSTS on HTTPS.
  if (https && !map['strict-transport-security']) {
    add('missing-hsts', 'low', 'Missing HSTS on HTTPS',
      'No Strict-Transport-Security header on an HTTPS response.', 'CWE-319');
  }

  // 5. MIME sniffing.
  if (isDocument && !map['x-content-type-options']) {
    add('missing-nosniff', 'low', 'Missing X-Content-Type-Options',
      'No X-Content-Type-Options: nosniff header.', 'CWE-16');
  }

  // 6. Information-leak headers.
  for (const leak of ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version']) {
    if (map[leak]) {
      add(`info-leak:${leak}`, 'informational', `Information disclosure via ${leak} header`,
        `${leak}: ${map[leak]}`, 'CWE-200');
    }
  }

  // 7. Cookie attributes.
  for (const line of cookies) {
    const { name, attrs, sameSite } = parseCookie(line);
    if (!name) continue;
    if (!attrs.has('httponly')) {
      add(`cookie-no-httponly:${name}`, 'low', `Cookie "${name}" missing HttpOnly`,
        `Set-Cookie: ${name}=… (no HttpOnly)`, 'CWE-1004');
    }
    if (https && !attrs.has('secure')) {
      add(`cookie-no-secure:${name}`, 'low', `Cookie "${name}" missing Secure`,
        `Set-Cookie: ${name}=… (no Secure on HTTPS)`, 'CWE-614');
    }
    if (!attrs.has('samesite') || sameSite === 'none') {
      add(`cookie-weak-samesite:${name}`, 'low', `Cookie "${name}" weak SameSite`,
        `Set-Cookie: ${name}=… (SameSite ${sameSite || 'unset'})`, 'CWE-1275');
    }
  }

  return out;
}

/** Merge new findings into an existing list, deduped by finding id (idempotent). */
export function mergeHeaderFindings(existing, incoming) {
  const byId = new Map();
  for (const f of Array.isArray(existing) ? existing : []) byId.set(f.id, f);
  for (const f of Array.isArray(incoming) ? incoming : []) byId.set(f.id, f);
  return Array.from(byId.values());
}
