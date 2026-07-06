import { describe, it, expect } from '@jest/globals';
import { analyzeHeaders, mergeHeaderFindings } from '../src/utils/headers';

const h = (obj) => Object.entries(obj).map(([name, value]) => ({ name, value }));

describe('analyzeHeaders — document protections', () => {
  it('flags missing CSP and clickjacking on a bare document', () => {
    const ids = analyzeHeaders({
      url: 'https://x.com/',
      type: 'main_frame',
      headers: h({ 'strict-transport-security': 'max-age=1', 'x-content-type-options': 'nosniff' }),
    }).map((f) => f.id);
    expect(ids).toContain('missing-csp');
    expect(ids).toContain('missing-frame-protection');
  });

  it('does not flag framing when CSP frame-ancestors is present', () => {
    const ids = analyzeHeaders({
      url: 'https://x.com/',
      type: 'main_frame',
      headers: h({ 'content-security-policy': "default-src 'self'; frame-ancestors 'none'" }),
    }).map((f) => f.id);
    expect(ids).not.toContain('missing-frame-protection');
    expect(ids).not.toContain('missing-csp');
  });

  it("flags unsafe-inline as weak CSP", () => {
    const ids = analyzeHeaders({
      url: 'https://x.com/',
      type: 'main_frame',
      headers: h({ 'content-security-policy': "script-src 'self' 'unsafe-inline'", 'x-frame-options': 'DENY' }),
    }).map((f) => f.id);
    expect(ids).toContain('weak-csp');
  });

  it('does not apply document checks to XHR responses', () => {
    const ids = analyzeHeaders({
      url: 'https://x.com/api',
      type: 'xmlhttprequest',
      headers: h({ 'strict-transport-security': 'max-age=1' }),
    }).map((f) => f.id);
    expect(ids).not.toContain('missing-csp');
    expect(ids).not.toContain('missing-frame-protection');
    expect(ids).not.toContain('missing-nosniff');
  });
});

describe('analyzeHeaders — CORS / HSTS / info-leak', () => {
  it('flags permissive CORS with credentials as high', () => {
    const f = analyzeHeaders({
      url: 'https://x.com/api',
      type: 'xmlhttprequest',
      headers: h({ 'access-control-allow-origin': '*', 'access-control-allow-credentials': 'true' }),
    }).find((x) => x.id === 'permissive-cors');
    expect(f).toBeTruthy();
    expect(f.severity).toBe('high');
  });

  it('flags missing HSTS only on https', () => {
    expect(analyzeHeaders({ url: 'https://x.com/api', type: 'xmlhttprequest', headers: [] }).map((f) => f.id)).toContain('missing-hsts');
    expect(analyzeHeaders({ url: 'http://x.com/api', type: 'xmlhttprequest', headers: [] }).map((f) => f.id)).not.toContain('missing-hsts');
  });

  it('flags Server / X-Powered-By as informational', () => {
    const findings = analyzeHeaders({
      url: 'https://x.com/', type: 'main_frame',
      headers: h({ server: 'nginx/1.2', 'x-powered-by': 'PHP/8' }),
    });
    const leaks = findings.filter((f) => f.id.startsWith('info-leak:'));
    expect(leaks.map((f) => f.id)).toEqual(expect.arrayContaining(['info-leak:server', 'info-leak:x-powered-by']));
    expect(leaks.every((f) => f.severity === 'informational')).toBe(true);
  });
});

describe('analyzeHeaders — cookies', () => {
  it('flags missing HttpOnly, Secure, and weak SameSite', () => {
    const ids = analyzeHeaders({
      url: 'https://x.com/',
      type: 'main_frame',
      headers: [{ name: 'set-cookie', value: 'sid=abc' }],
    }).map((f) => f.id);
    expect(ids).toContain('cookie-no-httponly:sid');
    expect(ids).toContain('cookie-no-secure:sid');
    expect(ids).toContain('cookie-weak-samesite:sid');
  });

  it('does not flag a hardened cookie', () => {
    const ids = analyzeHeaders({
      url: 'https://x.com/',
      type: 'main_frame',
      headers: [{ name: 'set-cookie', value: 'sid=abc; HttpOnly; Secure; SameSite=Lax' }],
    }).map((f) => f.id);
    expect(ids.some((id) => id.startsWith('cookie-'))).toBe(false);
  });

  it('flags SameSite=None as weak', () => {
    const ids = analyzeHeaders({
      url: 'https://x.com/',
      type: 'main_frame',
      headers: [{ name: 'set-cookie', value: 'sid=abc; HttpOnly; Secure; SameSite=None' }],
    }).map((f) => f.id);
    expect(ids).toContain('cookie-weak-samesite:sid');
  });
});

describe('mergeHeaderFindings', () => {
  it('dedupes by id and keeps the newest', () => {
    const a = [{ id: 'missing-csp', severity: 'medium' }];
    const b = [{ id: 'missing-csp', severity: 'medium' }, { id: 'missing-hsts', severity: 'low' }];
    const merged = mergeHeaderFindings(a, b);
    expect(merged).toHaveLength(2);
    expect(merged.map((f) => f.id).sort()).toEqual(['missing-csp', 'missing-hsts']);
  });
});
