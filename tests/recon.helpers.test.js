import { describe, it, expect } from '@jest/globals';
import {
  buildReconFileUrls,
  normalizeEndpoint,
  isSameOrigin,
  hostFromUrl,
  isHostAllowed,
} from '../src/utils/reconHelpers';

describe('buildReconFileUrls', () => {
  it('builds standard recon file URLs from an origin', () => {
    const urls = buildReconFileUrls('https://example.com');
    expect(urls).toEqual(
      expect.arrayContaining([
        'https://example.com/robots.txt',
        'https://example.com/sitemap.xml',
        'https://example.com/.well-known/security.txt',
      ])
    );
  });

  it('handles an origin with a trailing slash', () => {
    const urls = buildReconFileUrls('https://example.com/');
    expect(urls).toContain('https://example.com/robots.txt');
  });

  it('derives the origin from a full page URL', () => {
    const urls = buildReconFileUrls('https://example.com/some/deep/page?x=1');
    expect(urls).toContain('https://example.com/robots.txt');
  });

  it('returns an empty array for an invalid input', () => {
    expect(buildReconFileUrls('')).toEqual([]);
    expect(buildReconFileUrls('not a url')).toEqual([]);
  });
});

describe('normalizeEndpoint', () => {
  it('resolves an absolute path against the page origin', () => {
    expect(normalizeEndpoint('/api/users', 'https://example.com/page')).toBe(
      'https://example.com/api/users'
    );
  });

  it('passes through a same-origin absolute URL', () => {
    expect(
      normalizeEndpoint('https://example.com/api/x', 'https://example.com/page')
    ).toBe('https://example.com/api/x');
  });

  it('returns null for a cross-origin URL', () => {
    expect(
      normalizeEndpoint('https://evil.com/api/x', 'https://example.com/page')
    ).toBeNull();
  });

  it('returns null for unparseable input', () => {
    expect(normalizeEndpoint('', 'https://example.com')).toBeNull();
    expect(normalizeEndpoint(undefined, 'https://example.com')).toBeNull();
  });
});

describe('isSameOrigin', () => {
  it('is true for matching origin', () => {
    expect(isSameOrigin('https://example.com/a', 'https://example.com/b')).toBe(true);
  });
  it('is false for different host', () => {
    expect(isSameOrigin('https://example.com/a', 'https://other.com/b')).toBe(false);
  });
  it('is false for different scheme', () => {
    expect(isSameOrigin('http://example.com/a', 'https://example.com/b')).toBe(false);
  });
  it('is false for unparseable input', () => {
    expect(isSameOrigin('nonsense', 'https://example.com')).toBe(false);
  });
});

describe('hostFromUrl', () => {
  it('extracts the hostname', () => {
    expect(hostFromUrl('https://example.com:8443/path')).toBe('example.com');
  });
  it('returns empty string for invalid input', () => {
    expect(hostFromUrl('garbage')).toBe('');
  });
});

describe('isHostAllowed (gating)', () => {
  it('permits everything when wildcard is present', () => {
    expect(isHostAllowed(['*'], 'example.com')).toBe(true);
  });
  it('permits an exact host match', () => {
    expect(isHostAllowed(['example.com'], 'example.com')).toBe(true);
  });
  it('permits a substring/lab match (e.g. localhost)', () => {
    expect(isHostAllowed(['localhost'], 'localhost')).toBe(true);
    expect(isHostAllowed(['dvwa'], 'dvwa.local')).toBe(true);
  });
  it('denies a host not in the allowlist', () => {
    expect(isHostAllowed(['example.com'], 'evil.com')).toBe(false);
  });
  it('denies when host is empty', () => {
    expect(isHostAllowed(['*'], '')).toBe(false);
  });
  it('denies when allowlist is not an array', () => {
    expect(isHostAllowed(undefined, 'example.com')).toBe(false);
  });
});
