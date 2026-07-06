import { describe, it, expect } from '@jest/globals';
import {
  normalizePattern,
  parseScopeText,
  matchesPattern,
  evaluateScope,
  isInScope,
  scopeFromAllowlist,
} from '../src/utils/scope';

describe('normalizePattern', () => {
  it('strips scheme, path, port and lowercases', () => {
    expect(normalizePattern('HTTPS://App.Example.com:8443/login?x=1')).toBe('app.example.com');
  });
  it('turns a leading dot into a wildcard', () => {
    expect(normalizePattern('.example.com')).toBe('*.example.com');
  });
  it('ignores comments and blanks', () => {
    expect(normalizePattern('# a comment')).toBe('');
    expect(normalizePattern('   ')).toBe('');
  });
});

describe('parseScopeText', () => {
  it('splits on newlines and commas, de-duplicates', () => {
    expect(parseScopeText('a.com, b.com\na.com\n# note\n*.c.com')).toEqual([
      'a.com',
      'b.com',
      '*.c.com',
    ]);
  });
});

describe('matchesPattern', () => {
  it('* matches everything', () => {
    expect(matchesPattern('anything.io', '*')).toBe(true);
  });
  it('wildcard matches apex and subdomains', () => {
    expect(matchesPattern('example.com', '*.example.com')).toBe(true);
    expect(matchesPattern('a.b.example.com', '*.example.com')).toBe(true);
  });
  it('wildcard does not match a different domain', () => {
    expect(matchesPattern('notexample.com', '*.example.com')).toBe(false);
    expect(matchesPattern('example.com.evil.com', '*.example.com')).toBe(false);
  });
  it('bare host is exact only', () => {
    expect(matchesPattern('example.com', 'example.com')).toBe(true);
    expect(matchesPattern('app.example.com', 'example.com')).toBe(false);
  });
});

describe('evaluateScope / isInScope', () => {
  const scope = { inScope: ['*.example.com'], outOfScope: ['admin.example.com'] };

  it('allows an in-scope subdomain', () => {
    expect(evaluateScope('https://app.example.com/x', scope)).toMatchObject({
      allowed: true,
      reason: 'in_scope',
    });
  });
  it('out-of-scope wins over in-scope', () => {
    expect(evaluateScope('https://admin.example.com/', scope)).toMatchObject({
      allowed: false,
      reason: 'out_of_scope',
    });
  });
  it('rejects a host not in scope', () => {
    expect(isInScope('https://other.com/', scope)).toBe(false);
  });
  it('empty in-scope means nothing is allowed', () => {
    expect(evaluateScope('https://x.com', { inScope: [], outOfScope: [] })).toMatchObject({
      allowed: false,
      reason: 'no_scope',
    });
  });
  it('flags an unparseable URL', () => {
    expect(evaluateScope('not a url', scope)).toMatchObject({ allowed: false, reason: 'bad_url' });
  });
});

describe('end-to-end: parse text → evaluate', () => {
  it('out-of-scope from parsed text wins over in-scope, incl. dotted normalization', () => {
    const scope = {
      inScope: parseScopeText('.example.com\napi.example.com'),
      outOfScope: parseScopeText('admin.example.com'),
    };
    // ".example.com" normalized to "*.example.com" → subdomains in scope
    expect(isInScope('https://app.example.com/', scope)).toBe(true);
    // out-of-scope exact host still wins
    expect(isInScope('https://admin.example.com/', scope)).toBe(false);
    // unrelated host rejected
    expect(isInScope('https://evil.com/', scope)).toBe(false);
  });
});

describe('scopeFromAllowlist', () => {
  it('keeps * and wildcards bare hosts', () => {
    expect(scopeFromAllowlist(['*'])).toEqual({ inScope: ['*'], outOfScope: [] });
    expect(scopeFromAllowlist(['example.com'])).toEqual({
      inScope: ['*.example.com'],
      outOfScope: [],
    });
  });
  it('defaults to * when empty', () => {
    expect(scopeFromAllowlist([])).toEqual({ inScope: ['*'], outOfScope: [] });
  });
});
