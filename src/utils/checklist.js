// Bug-bounty methodology checklist, synthesized from public, industry-standard
// sources so it can be imported into the extension and tracked per target.
//
// Sources (all freely available, see akr3ch/BugBountyBooks):
//   - OWASP Web Security Testing Guide v4.2  (WSTG-* ids below are the canonical
//     test ids: https://owasp.org/www-project-web-security-testing-guide/)
//   - OWASP API Security Top 10 (2023)       (API-* ids)
//   - zseano's methodology                   (practical hunting workflow items)
//
// SCOPE & SAFETY: this is a *checklist of what to test*, not an attack runner.
// Only run any of these tests against assets that are explicitly in-scope for a
// program you are authorized to test. `payloadKey` links an item to a benign
// probe set in payloads.js; it never auto-fires anything.

/**
 * @typedef {Object} ChecklistItem
 * @property {string} id         Stable id, used as the storage key for progress.
 * @property {string} ref        Source reference (WSTG / API / ZSEANO).
 * @property {string} title      What to test.
 * @property {string} [payloadKey] Key into PAYLOADS (payloads.js) when relevant.
 *
 * @typedef {Object} ChecklistCategory
 * @property {string} id
 * @property {string} name
 * @property {string} source
 * @property {ChecklistItem[]} items
 */

/** @type {ChecklistCategory[]} */
export const CHECKLIST = [
  {
    id: 'recon',
    name: 'Recon & Information Gathering',
    source: 'WSTG-INFO',
    items: [
      { id: 'recon-search-discovery', ref: 'WSTG-INFO-01', title: 'Search engine / Google-dork discovery (leaked files, params, subdomains)' },
      { id: 'recon-fingerprint-server', ref: 'WSTG-INFO-02', title: 'Fingerprint web server (headers, error pages)' },
      { id: 'recon-metafiles', ref: 'WSTG-INFO-03', title: 'Review metafiles: robots.txt, sitemap.xml, security.txt' },
      { id: 'recon-enumerate-apps', ref: 'WSTG-INFO-04', title: 'Enumerate apps/subdomains on host (vhosts, ports)' },
      { id: 'recon-content-leakage', ref: 'WSTG-INFO-05', title: 'Review page source / JS files for info leakage (keys, endpoints, comments)' },
      { id: 'recon-entry-points', ref: 'WSTG-INFO-06', title: 'Identify all entry points (params, headers, uploads, APIs)' },
      { id: 'recon-fingerprint-framework', ref: 'WSTG-INFO-08', title: 'Fingerprint framework / tech stack (templating engine matters for SSTI)' },
      { id: 'recon-architecture', ref: 'WSTG-INFO-10', title: 'Map application architecture (CDNs, WAFs, microservices, 3rd-party assets)' },
    ],
  },
  {
    id: 'config',
    name: 'Configuration & Deployment',
    source: 'WSTG-CONF',
    items: [
      { id: 'conf-backups', ref: 'WSTG-CONF-04', title: 'Old, backup, and unreferenced files (.bak, .old, .git, .env)' },
      { id: 'conf-admin', ref: 'WSTG-CONF-05', title: 'Exposed admin / infra interfaces' },
      { id: 'conf-http-methods', ref: 'WSTG-CONF-06', title: 'Test HTTP methods (PUT/DELETE/TRACE, verb tampering)' },
      { id: 'conf-hsts', ref: 'WSTG-CONF-07', title: 'HTTP Strict Transport Security present/correct' },
      { id: 'conf-subdomain-takeover', ref: 'WSTG-CONF-10', title: 'Subdomain takeover (dangling CNAME to unclaimed service)' },
      { id: 'conf-cloud-storage', ref: 'WSTG-CONF-11', title: 'Cloud storage perms (open/writable S3 buckets, etc.)' },
    ],
  },
  {
    id: 'auth',
    name: 'Authentication',
    source: 'WSTG-ATHN',
    items: [
      { id: 'athn-default-creds', ref: 'WSTG-ATHN-02', title: 'Default / weak credentials' },
      { id: 'athn-lockout', ref: 'WSTG-ATHN-03', title: 'Weak or missing lockout / rate limiting on login' },
      { id: 'athn-bypass', ref: 'WSTG-ATHN-04', title: 'Authentication bypass (forced browsing, response tampering)' },
      { id: 'athn-2fa', ref: 'WSTG-ATHN-04', title: '2FA bypass (reuse, missing server-side check, race)' },
      { id: 'athn-reset', ref: 'WSTG-ATHN-09', title: 'Password change/reset flaws (token leakage, host-header poisoning)' },
      { id: 'athn-oauth', ref: 'WSTG-ATHN-10', title: 'OAuth/SSO flaws (redirect_uri validation, state, token leakage)' },
    ],
  },
  {
    id: 'session',
    name: 'Session Management',
    source: 'WSTG-SESS',
    items: [
      { id: 'sess-cookie-attrs', ref: 'WSTG-SESS-02', title: 'Cookie attributes (HttpOnly, Secure, SameSite, scope)' },
      { id: 'sess-fixation', ref: 'WSTG-SESS-03', title: 'Session fixation (token unchanged after login)' },
      { id: 'sess-csrf', ref: 'WSTG-SESS-05', title: 'CSRF on state-changing requests (token present + validated)' },
      { id: 'sess-logout', ref: 'WSTG-SESS-06', title: 'Logout actually invalidates session server-side' },
      { id: 'sess-timeout', ref: 'WSTG-SESS-07', title: 'Session timeout enforced' },
    ],
  },
  {
    id: 'authz',
    name: 'Authorization (Access Control)',
    source: 'WSTG-ATHZ',
    items: [
      { id: 'authz-path-traversal', ref: 'WSTG-ATHZ-01', title: 'Directory traversal / file include', payloadKey: 'pathTraversal' },
      { id: 'authz-bypass', ref: 'WSTG-ATHZ-02', title: 'Authorization bypass (access another role/tenant)' },
      { id: 'authz-privesc', ref: 'WSTG-ATHZ-03', title: 'Privilege escalation (function-level access control)' },
      { id: 'authz-idor', ref: 'WSTG-ATHZ-04', title: 'IDOR — swap ids/UUIDs between two accounts you control' },
    ],
  },
  {
    id: 'input',
    name: 'Input Validation / Injection',
    source: 'WSTG-INPV',
    items: [
      { id: 'inpv-xss-reflected', ref: 'WSTG-INPV-01', title: 'Reflected XSS', payloadKey: 'xss' },
      { id: 'inpv-xss-stored', ref: 'WSTG-INPV-02', title: 'Stored XSS (rendered later/elsewhere — emails, admin panels)', payloadKey: 'xss' },
      { id: 'inpv-hpp', ref: 'WSTG-INPV-04', title: 'HTTP Parameter Pollution (duplicate params)' },
      { id: 'inpv-sqli', ref: 'WSTG-INPV-05', title: 'SQL injection (incl. blind / second-order)', payloadKey: 'sqli' },
      { id: 'inpv-xpath', ref: 'WSTG-INPV-09', title: 'XPath injection', payloadKey: 'xpath' },
      { id: 'inpv-cmdi', ref: 'WSTG-INPV-12', title: 'OS command injection', payloadKey: 'cmdi' },
      { id: 'inpv-crlf', ref: 'WSTG-INPV-15', title: 'CRLF / HTTP response splitting & smuggling' },
      { id: 'inpv-host-header', ref: 'WSTG-INPV-17', title: 'Host header injection (cache poisoning, reset poisoning)' },
      { id: 'inpv-ssti', ref: 'WSTG-INPV-18', title: 'Server-side template injection (try {{7*7}} / ${7*7})' },
      { id: 'inpv-ssrf', ref: 'WSTG-INPV-19', title: 'SSRF (webhooks, URL params, file imports)', payloadKey: 'ssrf' },
      { id: 'inpv-xxe', ref: 'WSTG-INPV-07', title: 'XXE — any XML/.docx/.xlsx/.svg upload or XML body' },
    ],
  },
  {
    id: 'errors-crypto',
    name: 'Error Handling & Crypto',
    source: 'WSTG-ERRH / WSTG-CRYP',
    items: [
      { id: 'errh-stacktrace', ref: 'WSTG-ERRH-02', title: 'Stack traces / verbose errors leak internals' },
      { id: 'cryp-tls', ref: 'WSTG-CRYP-01', title: 'Weak TLS config' },
      { id: 'cryp-cleartext', ref: 'WSTG-CRYP-03', title: 'Sensitive data over unencrypted channels' },
    ],
  },
  {
    id: 'logic',
    name: 'Business Logic',
    source: 'WSTG-BUSL',
    items: [
      { id: 'busl-data-validation', ref: 'WSTG-BUSL-01', title: 'Logic data validation (negative qty, price tampering)' },
      { id: 'busl-forge-requests', ref: 'WSTG-BUSL-02', title: 'Forge/replay requests outside intended flow' },
      { id: 'busl-limits-race', ref: 'WSTG-BUSL-05', title: 'Function-use limits & race conditions (coupons, invites, transfers)' },
      { id: 'busl-workflow', ref: 'WSTG-BUSL-06', title: 'Workflow circumvention (skip steps)' },
      { id: 'busl-file-upload', ref: 'WSTG-BUSL-09', title: 'Malicious/unexpected file upload' },
    ],
  },
  {
    id: 'client',
    name: 'Client-Side',
    source: 'WSTG-CLNT',
    items: [
      { id: 'clnt-dom-xss', ref: 'WSTG-CLNT-01', title: 'DOM-based XSS (sinks: innerHTML, location.hash)', payloadKey: 'xss' },
      { id: 'clnt-open-redirect', ref: 'WSTG-CLNT-04', title: 'Open redirect (url=, redirect=, next=, r=, u=)' },
      { id: 'clnt-cors', ref: 'WSTG-CLNT-07', title: 'CORS misconfig (reflects arbitrary Origin, credentials)' },
      { id: 'clnt-clickjacking', ref: 'WSTG-CLNT-09', title: 'Clickjacking (missing X-Frame-Options/CSP frame-ancestors)' },
      { id: 'clnt-postmessage', ref: 'WSTG-CLNT-11', title: 'postMessage / web messaging origin checks' },
      { id: 'clnt-storage', ref: 'WSTG-CLNT-12', title: 'Sensitive data in localStorage/sessionStorage' },
    ],
  },
  {
    id: 'api',
    name: 'API (OWASP API Top 10 2023)',
    source: 'OWASP-API',
    items: [
      { id: 'api-bola', ref: 'API1:2023', title: 'Broken Object Level Authorization (BOLA / API IDOR)' },
      { id: 'api-auth', ref: 'API2:2023', title: 'Broken authentication (weak JWT, no expiry, alg=none)' },
      { id: 'api-bopla', ref: 'API3:2023', title: 'Broken Object Property Level Auth (mass assignment, excessive data)' },
      { id: 'api-resource', ref: 'API4:2023', title: 'Unrestricted resource consumption (no rate limit/pagination caps)' },
      { id: 'api-bfla', ref: 'API5:2023', title: 'Broken Function Level Authorization (admin endpoints as user)' },
      { id: 'api-ssrf', ref: 'API7:2023', title: 'Server-side request forgery via API', payloadKey: 'ssrf' },
      { id: 'api-inventory', ref: 'API9:2023', title: 'Improper inventory (old /v1, staging, undocumented endpoints)' },
    ],
  },
  {
    id: 'workflow',
    name: "Hunter Workflow (zseano)",
    source: 'ZSEANO',
    items: [
      { id: 'zs-pick-target', ref: 'ZSEANO', title: 'Understand the app deeply before testing — map every feature' },
      { id: 'zs-two-accounts', ref: 'ZSEANO', title: 'Use two accounts (A & B) and test cross-account access on every action' },
      { id: 'zs-reflected-params', ref: 'ZSEANO', title: 'Track every param reflected in the response / DOM' },
      { id: 'zs-js-files', ref: 'ZSEANO', title: 'Read & diff JS files over time for new/hidden endpoints' },
      { id: 'zs-new-features', ref: 'ZSEANO', title: 'Re-test when new features ship (changelogs, blog, Twitter)' },
      { id: 'zs-read-policy', ref: 'ZSEANO', title: 'Read the program policy & confirm scope BEFORE testing' },
    ],
  },
];

// ----- Pure helpers (no chrome.* / network — unit-testable) -----------------

/** Flatten all items across categories into a single array. */
export function getAllChecklistItems() {
  return CHECKLIST.flatMap((cat) =>
    cat.items.map((item) => ({ ...item, categoryId: cat.id, categoryName: cat.name })),
  );
}

/** Total number of checklist items. */
export function countChecklistItems() {
  return CHECKLIST.reduce((n, cat) => n + cat.items.length, 0);
}

/**
 * Build a fresh per-target progress object: { [itemId]: 'todo' }.
 * Persist this in chrome.storage keyed by the target/program.
 */
export function createChecklistProgress() {
  const progress = {};
  for (const item of getAllChecklistItems()) progress[item.id] = 'todo';
  return progress;
}

/** Allowed states for a checklist item. */
export const CHECKLIST_STATES = ['todo', 'testing', 'pass', 'finding', 'na'];

/**
 * Summarize progress: counts per state + percent of items that are no longer 'todo'.
 * @param {Record<string,string>} progress
 */
export function summarizeProgress(progress = {}) {
  const total = countChecklistItems();
  const counts = Object.fromEntries(CHECKLIST_STATES.map((s) => [s, 0]));
  for (const item of getAllChecklistItems()) {
    const state = progress[item.id] || 'todo';
    if (state in counts) counts[state] += 1;
  }
  const touched = total - counts.todo;
  return { total, counts, percentComplete: total ? Math.round((touched / total) * 100) : 0 };
}
