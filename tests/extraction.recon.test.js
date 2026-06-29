import { describe, it, expect, beforeEach } from '@jest/globals';
import {
  extractPageRecon,
  findInlineEndpoints,
  fingerprintFrameworks,
} from '../src/utils/extraction';

function setBody(html) {
  document.body.innerHTML = html;
}

describe('findInlineEndpoints', () => {
  it('extracts absolute-path API endpoints', () => {
    const src = `fetch('/api/users'); axios.get("/api/v2/orders");`;
    const eps = findInlineEndpoints(src);
    expect(eps).toEqual(expect.arrayContaining(['/api/users', '/api/v2/orders']));
  });

  it('extracts fully-qualified URLs', () => {
    const src = `const u = "https://api.example.com/data";`;
    expect(findInlineEndpoints(src)).toContain('https://api.example.com/data');
  });

  it('de-duplicates repeated endpoints', () => {
    const src = `fetch('/api/x'); fetch('/api/x');`;
    const eps = findInlineEndpoints(src);
    expect(eps.filter((e) => e === '/api/x')).toHaveLength(1);
  });

  it('ignores plain strings that are not paths or urls', () => {
    const src = `const msg = "hello world"; const n = 42;`;
    expect(findInlineEndpoints(src)).toEqual([]);
  });

  it('returns an array for empty input', () => {
    expect(findInlineEndpoints('')).toEqual([]);
    expect(findInlineEndpoints(undefined)).toEqual([]);
  });
});

describe('fingerprintFrameworks', () => {
  it('detects React when window.React is present', () => {
    const win = { React: {} };
    expect(fingerprintFrameworks(win, document)).toContain('React');
  });

  it('detects jQuery when window.jQuery is present', () => {
    const win = { jQuery: () => {} };
    expect(fingerprintFrameworks(win, document)).toContain('jQuery');
  });

  it('detects a framework from a script src hint', () => {
    setBody('<script src="https://cdn.example.com/vue@3/vue.global.js"></script>');
    const names = fingerprintFrameworks({}, document);
    expect(names).toContain('Vue');
  });

  it('returns an array and de-duplicates', () => {
    const win = { React: {}, jQuery: () => {} };
    const names = fingerprintFrameworks(win, document);
    expect(Array.isArray(names)).toBe(true);
    expect(new Set(names).size).toBe(names.length);
  });
});

describe('extractPageRecon', () => {
  beforeEach(() => setBody(''));

  it('captures title and meta tags', () => {
    document.head.innerHTML =
      '<meta name="generator" content="WordPress 6.1"><meta name="csrf-token" content="abc">';
    document.title = 'My App';
    const recon = extractPageRecon({ documentRef: document, windowRef: {} });
    expect(recon.title).toBe('My App');
    expect(recon.meta.generator).toBe('WordPress 6.1');
    expect(recon.meta['csrf-token']).toBe('abc');
  });

  it('captures HTML comments', () => {
    setBody('<!-- TODO: remove debug endpoint /api/debug --><div>x</div>');
    const recon = extractPageRecon({ documentRef: document, windowRef: {} });
    expect(recon.comments.join(' ')).toContain('/api/debug');
  });

  it('extracts inline-script endpoints', () => {
    setBody('<script>fetch("/api/secret");</script>');
    const recon = extractPageRecon({ documentRef: document, windowRef: {} });
    expect(recon.endpoints).toContain('/api/secret');
  });

  it('summarises forms with action and method', () => {
    setBody(
      '<form action="/login" method="post"><input name="u"></form><form action="/search"></form>'
    );
    const recon = extractPageRecon({ documentRef: document, windowRef: {} });
    expect(recon.forms).toHaveLength(2);
    expect(recon.forms[0]).toMatchObject({ action: '/login', method: 'post' });
    expect(recon.forms[1].method).toBe('get');
  });

  it('inventories links and buttons', () => {
    setBody(
      '<a href="/about">About</a><a href="/admin">Admin</a><button>Go</button>'
    );
    const recon = extractPageRecon({ documentRef: document, windowRef: {} });
    expect(recon.links).toEqual(expect.arrayContaining(['/about', '/admin']));
    expect(recon.buttonCount).toBe(1);
  });

  it('captures non-HttpOnly cookie names only (names, not values)', () => {
    const recon = extractPageRecon({
      documentRef: { ...mockDoc(), cookie: 'sessionid=secret; theme=dark' },
      windowRef: {},
    });
    expect(recon.cookieNames).toEqual(expect.arrayContaining(['sessionid', 'theme']));
    // values must never be captured
    expect(JSON.stringify(recon.cookieNames)).not.toContain('secret');
  });

  it('captures storage keys without values', () => {
    const windowRef = {
      localStorage: { length: 1, key: () => 'auth_token' },
      sessionStorage: { length: 1, key: () => 'cart' },
    };
    const recon = extractPageRecon({ documentRef: document, windowRef });
    expect(recon.localStorageKeys).toContain('auth_token');
    expect(recon.sessionStorageKeys).toContain('cart');
  });

  it('survives storage getters that throw (e.g. Brave Shields / blocked storage)', () => {
    const windowRef = {};
    // Property access itself throws a SecurityError, like blocked DOM storage.
    Object.defineProperty(windowRef, 'localStorage', {
      get() {
        throw new DOMException('Access is denied for this document', 'SecurityError');
      },
    });
    Object.defineProperty(windowRef, 'sessionStorage', {
      get() {
        throw new DOMException('Access is denied for this document', 'SecurityError');
      },
    });
    let recon;
    expect(() => {
      recon = extractPageRecon({ documentRef: document, windowRef });
    }).not.toThrow();
    expect(recon.localStorageKeys).toEqual([]);
    expect(recon.sessionStorageKeys).toEqual([]);
  });

  it('includes framework fingerprint', () => {
    setBody('<script src="/react.production.min.js"></script>');
    const recon = extractPageRecon({ documentRef: document, windowRef: { React: {} } });
    expect(recon.frameworks).toContain('React');
  });

  it('returns a well-formed object even on a bare page', () => {
    const recon = extractPageRecon({ documentRef: document, windowRef: {} });
    expect(recon).toMatchObject({
      title: expect.any(String),
      meta: expect.any(Object),
      comments: expect.any(Array),
      endpoints: expect.any(Array),
      forms: expect.any(Array),
      links: expect.any(Array),
      frameworks: expect.any(Array),
    });
  });
});

// Minimal document-like stub for the cookie test (avoids mutating real document.cookie).
function mockDoc() {
  return {
    title: '',
    head: document.head,
    body: document.body,
    querySelectorAll: document.querySelectorAll.bind(document),
    createNodeIterator: document.createNodeIterator
      ? document.createNodeIterator.bind(document)
      : undefined,
  };
}
