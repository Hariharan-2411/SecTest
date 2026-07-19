import { describe, it, expect } from '@jest/globals';
import { analyzeConsoleEvents } from '../src/utils/consoleRecon';

// A realistically-shaped JWT (matches secrets.js's jwt pattern).
const JWT =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';

describe('analyzeConsoleEvents', () => {
  it('pulls endpoints out of an error stack, stripping the line:col suffix', () => {
    const r = analyzeConsoleEvents([
      { kind: 'onerror', message: 'Uncaught TypeError', stack: 'at https://api.example.com/v2/users:42:15' },
    ]);
    expect(r.endpoints).toContain('https://api.example.com/v2/users');
  });

  it('extracts secrets from error text via findSecrets, preview only (never raw)', () => {
    const r = analyzeConsoleEvents([{ kind: 'error', message: `auth failed for token ${JWT}` }]);
    expect(r.secrets.some((s) => s.type === 'jwt')).toBe(true);
    expect(JSON.stringify(r.secrets)).not.toContain(JWT); // masked/previewed, not raw
  });

  it('normalizes a CSP violation and adds an http blockedURI to endpoints', () => {
    const r = analyzeConsoleEvents([
      { kind: 'csp', violatedDirective: 'script-src', blockedURI: 'https://evil.cdn.com/x.js' },
    ]);
    expect(r.cspViolations).toEqual([{ directive: 'script-src', blockedURI: 'https://evil.cdn.com/x.js' }]);
    expect(r.endpoints).toContain('https://evil.cdn.com/x.js');
  });

  it('keeps an inline CSP violation but adds no endpoint for it', () => {
    const r = analyzeConsoleEvents([
      { kind: 'csp', violatedDirective: 'script-src', blockedURI: 'inline' },
    ]);
    expect(r.cspViolations).toEqual([{ directive: 'script-src', blockedURI: 'inline' }]);
    expect(r.endpoints).toEqual([]);
  });

  it('records a trimmed error signature from the message', () => {
    const r = analyzeConsoleEvents([{ kind: 'error', message: '  Cannot read property foo of undefined  ' }]);
    expect(r.errorSignatures).toContain('Cannot read property foo of undefined');
  });

  it('dedupes endpoints and CSP violations across events', () => {
    const r = analyzeConsoleEvents([
      { kind: 'csp', violatedDirective: 'script-src', blockedURI: 'https://evil.cdn.com/x.js' },
      { kind: 'csp', violatedDirective: 'script-src', blockedURI: 'https://evil.cdn.com/x.js' },
      { kind: 'error', message: 'x https://a.example.com/p https://a.example.com/p' },
    ]);
    expect(r.cspViolations).toHaveLength(1);
    expect(r.endpoints.filter((e) => e === 'https://a.example.com/p')).toHaveLength(1);
  });

  it('never throws on garbage input', () => {
    expect(() => analyzeConsoleEvents(null)).not.toThrow();
    expect(analyzeConsoleEvents(null)).toEqual({ endpoints: [], secrets: [], cspViolations: [], errorSignatures: [] });
    expect(() => analyzeConsoleEvents([null, undefined, 5, {}])).not.toThrow();
  });
});
