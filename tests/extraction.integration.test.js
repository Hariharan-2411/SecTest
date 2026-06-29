import { describe, it, expect, beforeAll } from '@jest/globals';
import fs from 'fs';
import path from 'path';
import { collectFields, extractPageRecon, findInlineEndpoints } from '../src/utils/extraction';

// End-to-end check of the extraction core against the project's real test page,
// mirroring what the content script does on scanPage / getPageRecon.
describe('extraction against test-page.html', () => {
  let result;
  let recon;
  let html;

  beforeAll(() => {
    html = fs.readFileSync(path.join(__dirname, '..', 'test-page.html'), 'utf8');
    document.documentElement.innerHTML = html;

    // Reproduce the page's open shadow root (jsdom does not run inline scripts
    // when assigning innerHTML), so the traversal path is genuinely exercised.
    const host = document.getElementById('shadow-host');
    if (host && host.attachShadow) {
      const root = host.attachShadow({ mode: 'open' });
      root.innerHTML =
        '<input type="text" name="shadow_secret">' +
        '<input type="hidden" name="csrf_token" value="shadow-csrf-123">';
    }

    result = collectFields(document.body, { scanId: 1 });
    recon = extractPageRecon({ documentRef: document, windowRef: window });
  });

  it('finds all the expected field types', () => {
    const types = Array.from(new Set(result.fields.map((f) => f.type)));
    expect(types).toEqual(expect.arrayContaining(['input', 'textarea', 'select', 'file']));
  });

  it('tags the hidden field correctly', () => {
    const hidden = result.fields.find((f) => f.name === 'hidden-field');
    expect(hidden).toBeDefined();
    expect(hidden.tags).toContain('hidden');
  });

  it('tags the password field', () => {
    const pw = result.fields.find((f) => f.name === 'password');
    expect(pw.tags).toContain('password');
  });

  it('tags the email fields', () => {
    const emails = result.fields.filter((f) => f.tags.includes('email'));
    expect(emails.length).toBeGreaterThanOrEqual(1);
  });

  it('tags the search query field', () => {
    const q = result.fields.find((f) => f.name === 'query');
    expect(q.tags).toContain('search');
  });

  it('tags the redirect-style url field', () => {
    const url = result.fields.find((f) => f.name === 'url');
    expect(url.tags).toContain('redirect-param');
  });

  it('tags file uploads', () => {
    const files = result.fields.filter((f) => f.tags.includes('file-upload'));
    expect(files.length).toBeGreaterThanOrEqual(3);
  });

  it('captures form actions/methods in recon', () => {
    expect(recon.forms.length).toBeGreaterThanOrEqual(4);
    for (const f of recon.forms) {
      expect(typeof f.method).toBe('string');
    }
  });

  it('assigns unique ids to every field', () => {
    const ids = result.fields.map((f) => f.uniqueId);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('keeps a live element reference for injection', () => {
    expect(result.fields.every((f) => f.element != null)).toBe(true);
  });

  it('descends into the open shadow root', () => {
    const shadowField = result.fields.find((f) => f.name === 'shadow_secret');
    expect(shadowField).toBeDefined();
    expect(shadowField.context).toBe('shadow');
  });

  it('tags the shadow-hosted csrf token', () => {
    const csrf = result.fields.find(
      (f) => f.name === 'csrf_token' && f.context === 'shadow'
    );
    expect(csrf).toBeDefined();
    expect(csrf.tags).toEqual(expect.arrayContaining(['hidden', 'csrf-token']));
  });

  it('tags the open-redirect and IDOR candidate params', () => {
    const next = result.fields.find((f) => f.name === 'next');
    const acct = result.fields.find((f) => f.name === 'account_id');
    expect(next.tags).toContain('redirect-param');
    expect(acct.tags).toContain('id-param');
  });

  it('discovers inline-script endpoints in the page source', () => {
    // The page references /api/v1/profile endpoints in an inline script.
    const eps = findInlineEndpoints(html);
    expect(eps.some((e) => e.includes('/api/v1/profile'))).toBe(true);
  });
});
