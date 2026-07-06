// Secret detection — pure, unit-testable (no chrome.*/network).
//
// Single source of truth for "does this text contain a likely credential?".
// Extracted from jsdiff.js so the passive page recon, the deep-JS scan, and the
// JS-change monitor all share ONE pattern set (no drift between them).
//
// SAFETY: we store only the MATCH SHAPE and a masked preview — never the full
// secret value in plaintext logs, storage, or UI. Detection is conservative:
// labeled high-signal patterns plus one generic assignment pattern gated by
// Shannon entropy, so placeholders like "your_api_key_here" don't fire.

// Conservative, low-false-positive labeled patterns.
const SECRET_PATTERNS = [
  { type: 'aws_access_key', re: /\bAKIA[0-9A-Z]{16}\b/g },
  { type: 'google_api_key', re: /\bAIza[0-9A-Za-z_\-]{35}\b/g },
  { type: 'slack_token', re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g },
  { type: 'stripe_key', re: /\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}\b/g },
  { type: 'github_token', re: /\bgh[posru]_[0-9A-Za-z]{36}\b/g },
  { type: 'jwt', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
  { type: 'private_key', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g },
];

// Generic "<secret-ish name> = '<value>'" assignment. The value is only treated
// as a secret when it looks random enough (entropy gate) and isn't an obvious
// placeholder — this is where false positives come from, so it's deliberately strict.
const GENERIC_ASSIGN_RE =
  /(?:api[_-]?key|apikey|secret|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|pwd)["']?\s*[:=]\s*["']([^"'\s]{8,120})["']/gi;

const PLACEHOLDER_RE =
  /^(?:x+|\.+|-+|_+|0+|example|test|changeme|placeholder|your[_-]?|redacted|null|none|undefined|true|false)/i;

/** Shannon entropy (bits/char) of a string. Higher = more random-looking. */
export function shannonEntropy(str) {
  const s = String(str || '');
  if (!s.length) return 0;
  const freq = Object.create(null);
  for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
  let h = 0;
  for (const ch in freq) {
    const p = freq[ch] / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

// A value is "secret-looking" when it's high-entropy, not a placeholder, and not
// obviously a URL/path/word (those trip the generic name match but aren't creds).
function looksSecret(value) {
  const v = String(value || '');
  if (v.length < 8) return false;
  if (PLACEHOLDER_RE.test(v)) return false;
  if (/^https?:\/\//i.test(v) || v.startsWith('/')) return false;
  if (/^\d+$/.test(v)) return false; // pure numbers (ids, timestamps)
  if (/^[a-z]+$/i.test(v)) return false; // a single lowercase/uppercase word
  return shannonEntropy(v) >= 3.0;
}

/** Mask a secret so logs never store the full value. */
export function maskSecret(value) {
  const v = String(value);
  if (v.length <= 8) return v[0] + '***';
  return v.slice(0, 4) + '…' + v.slice(-4);
}

/**
 * Scan text for likely secrets.
 * @returns {{type:string, preview:string}[]} deduped by type+preview; never raw values.
 */
export function findSecrets(text) {
  const src = typeof text === 'string' ? text : '';
  const out = [];
  const seen = new Set();

  const push = (type, raw) => {
    const preview = maskSecret(raw);
    const key = type + ':' + preview;
    if (!seen.has(key)) {
      seen.add(key);
      out.push({ type, preview });
    }
  };

  for (const { type, re } of SECRET_PATTERNS) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(src))) push(type, m[0]);
  }

  GENERIC_ASSIGN_RE.lastIndex = 0;
  let g;
  while ((g = GENERIC_ASSIGN_RE.exec(src))) {
    if (looksSecret(g[1])) push('generic_secret', g[1]);
  }

  return out;
}

export { SECRET_PATTERNS };
