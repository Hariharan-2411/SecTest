// Passive console/error recon — pure, unit-testable (no chrome.*/network).
//
// Normalizes a batch of captured console/error/CSP events (from the MAIN-world
// observer) into recon data: endpoints (mined from stack traces / blocked URIs),
// secrets (reusing secrets.findSecrets on the error text), CSP-violation
// summaries, and bounded error signatures. Observe-only — it derives nothing the
// events didn't already carry, and never includes raw secret values.

import { findSecrets } from './secrets';

const URL_RE = /https?:\/\/[^\s"'<>()]+/g;
const CAPS = { endpoints: 100, signatures: 50, csp: 50 };

function str(v) {
  return typeof v === 'string' ? v : v == null ? '' : String(v);
}

// Strip a trailing :line:col (stack frames) and trailing punctuation from a URL.
function trimUrl(u) {
  return str(u).replace(/(?::\d+)+$/, '').replace(/[),.;:'"]+$/, '');
}

/**
 * Normalize captured console/error/CSP events into recon data. Pure; never throws.
 * @param {{kind:string,message?:string,stack?:string,source?:string,violatedDirective?:string,blockedURI?:string}[]} events
 * @returns {{endpoints:string[], secrets:{type:string,preview:string}[], cspViolations:{directive:string,blockedURI:string}[], errorSignatures:string[]}}
 */
export function analyzeConsoleEvents(events) {
  const list = Array.isArray(events) ? events : [];
  const endpoints = new Set();
  const signatures = new Set();
  const cspSeen = new Set();
  const cspViolations = [];
  let text = '';

  for (const e of list) {
    if (!e || typeof e !== 'object') continue;
    if (e.kind === 'csp') {
      const directive = str(e.violatedDirective).slice(0, 80);
      const blockedURI = str(e.blockedURI).slice(0, 300);
      if (directive || blockedURI) {
        const key = directive + '|' + blockedURI;
        if (!cspSeen.has(key)) {
          cspSeen.add(key);
          cspViolations.push({ directive, blockedURI });
        }
      }
      if (/^https?:\/\//i.test(blockedURI)) endpoints.add(trimUrl(blockedURI));
      continue;
    }
    const chunk = `${str(e.message)} ${str(e.stack)} ${str(e.source)}`;
    text += ' ' + chunk;
    for (const m of chunk.match(URL_RE) || []) {
      const u = trimUrl(m);
      if (u) endpoints.add(u);
    }
    const sig = str(e.message).replace(/\s+/g, ' ').trim().slice(0, 200);
    if (sig) signatures.add(sig);
  }

  let secrets = [];
  try {
    secrets = findSecrets(text) || [];
  } catch (_) {
    secrets = [];
  }

  return {
    endpoints: [...endpoints].slice(0, CAPS.endpoints),
    secrets,
    cspViolations: cspViolations.slice(0, CAPS.csp),
    errorSignatures: [...signatures].slice(0, CAPS.signatures),
  };
}
