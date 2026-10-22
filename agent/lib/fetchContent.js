'use strict';
// Fetch an in-scope URL's body into a bounded temp dir, for content scanners
// (trufflehog/gitleaks) that scan files rather than a live target. The CALLER
// enforces scope before calling. JS-link following is a documented Phase-1
// follow-up; v1 scans the fetched page body (incl. inline scripts).
const { mkdtempSync, writeFileSync, rmSync } = require('fs');
const { tmpdir } = require('os');
const { join } = require('path');

async function fetchToTempDir(url, { maxBytes = 2 * 1024 * 1024, timeoutMs = 15000, fetchImpl } = {}) {
  const doFetch = fetchImpl || (typeof fetch !== 'undefined' ? fetch : null);
  const dir = mkdtempSync(join(tmpdir(), 'iris-content-'));
  const cleanup = () => { try { rmSync(dir, { recursive: true, force: true }); } catch (_) {} };
  if (!doFetch) return { dir, files: [], cleanup, error: 'no_fetch' };
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await doFetch(url, { signal: ctrl.signal, redirect: 'follow' });
    let body = await res.text();
    if (body.length > maxBytes) body = body.slice(0, maxBytes); // bound it
    const f = join(dir, 'page.txt');
    writeFileSync(f, body);
    return { dir, files: [f], cleanup };
  } catch (e) {
    return { dir, files: [], cleanup, error: String(e && e.message) };
  } finally {
    clearTimeout(timer);
  }
}

module.exports = { fetchToTempDir };
