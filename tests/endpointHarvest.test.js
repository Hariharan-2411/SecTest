import { describe, it, expect } from '@jest/globals';
import { extractEndpoints } from '../src/utils/endpointHarvest';

const scope = { inScope: ['*.example.com', 'example.com', 'juiceshop'], outOfScope: [] };

describe('extractEndpoints — mine API/app routes from JS/HTML text', () => {
  it('pulls quoted rooted paths out of a JS bundle and makes them absolute + in-scope', () => {
    const js = `const base='/rest/products/search';fetch("/api/user/whoami");var x="/rest/admin/application-configuration";`;
    const out = extractEndpoints(js, 'http://juiceshop:3000', scope);
    expect(out).toContain('http://juiceshop:3000/rest/products/search');
    expect(out).toContain('http://juiceshop:3000/api/user/whoami');
    expect(out).toContain('http://juiceshop:3000/rest/admin/application-configuration');
  });

  it('keeps absolute in-scope URLs and drops out-of-scope ones', () => {
    const html = `<a href="https://app.example.com/dashboard">x</a> <script src="https://evil.test/x.js">`;
    const out = extractEndpoints(html, 'https://app.example.com', scope);
    expect(out).toContain('https://app.example.com/dashboard');
    expect(out.some((u) => u.includes('evil.test'))).toBe(false);
  });

  it('skips static assets (js/css/img/fonts/maps) — we want endpoints, not files', () => {
    const js = `"/main.js","/styles.css","/logo.png","/font.woff2","/app.js.map","/rest/products/search"`;
    const out = extractEndpoints(js, 'http://juiceshop:3000', scope);
    expect(out).toContain('http://juiceshop:3000/rest/products/search');
    expect(out.some((u) => /\.(js|css|png|woff2|map)$/.test(u))).toBe(false);
  });

  it('dedupes and never throws on garbage', () => {
    expect(() => extractEndpoints(null, null, null)).not.toThrow();
    expect(extractEndpoints('', 'http://x', scope)).toEqual([]);
    const dup = extractEndpoints('"/a/b" "/a/b" "/a/b"', 'http://juiceshop:3000', scope);
    expect(dup.length).toBe(1);
  });
});
