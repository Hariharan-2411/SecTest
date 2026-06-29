import { describe, it, expect } from '@jest/globals';
import { computeTags } from '../src/utils/extraction';

// computeTags operates on the metadata object produced by extractFieldMetadata,
// so tests pass plain objects rather than DOM nodes.

describe('computeTags - hidden', () => {
  it('tags hidden fields', () => {
    expect(computeTags({ type: 'input', subType: 'hidden', name: 'x', hidden: true })).toContain(
      'hidden'
    );
  });
  it('does not tag visible fields as hidden', () => {
    expect(computeTags({ type: 'input', subType: 'text', name: 'x', hidden: false })).not.toContain(
      'hidden'
    );
  });
});

describe('computeTags - csrf-token', () => {
  it('tags a hidden field whose name looks like a csrf token', () => {
    const tags = computeTags({ subType: 'hidden', hidden: true, name: 'csrf_token', value: 'abc' });
    expect(tags).toContain('csrf-token');
  });
  it('matches common variants (authenticity_token, __requestverificationtoken, xsrf)', () => {
    for (const name of ['authenticity_token', '__RequestVerificationToken', 'xsrf-token', 'csrfmiddlewaretoken']) {
      expect(computeTags({ subType: 'hidden', hidden: true, name, value: 'v' })).toContain('csrf-token');
    }
  });
  it('does not tag a visible text field named token', () => {
    expect(
      computeTags({ subType: 'text', hidden: false, name: 'token' })
    ).not.toContain('csrf-token');
  });
});

describe('computeTags - file-upload', () => {
  it('tags file inputs', () => {
    expect(computeTags({ type: 'file', subType: 'file', name: 'doc' })).toContain('file-upload');
  });
});

describe('computeTags - password / email / search', () => {
  it('tags password fields', () => {
    expect(computeTags({ type: 'input', subType: 'password', name: 'pw' })).toContain('password');
  });
  it('tags email fields by subType', () => {
    expect(computeTags({ type: 'input', subType: 'email', name: 'e' })).toContain('email');
  });
  it('tags email fields by name when subType is text', () => {
    expect(computeTags({ type: 'input', subType: 'text', name: 'user_email' })).toContain('email');
  });
  it('tags search fields', () => {
    expect(computeTags({ type: 'input', subType: 'search', name: 'q' })).toContain('search');
  });
  it('tags fields named q/query/search/keyword as search', () => {
    for (const name of ['q', 'query', 'search', 'keyword', 's']) {
      expect(computeTags({ type: 'input', subType: 'text', name })).toContain('search');
    }
  });
});

describe('computeTags - redirect-param (open redirect candidates)', () => {
  it('tags fields whose name suggests a redirect target', () => {
    for (const name of ['url', 'next', 'redirect', 'redirect_uri', 'return', 'returnUrl', 'dest', 'continue', 'callback']) {
      expect(computeTags({ type: 'input', subType: 'text', name })).toContain('redirect-param');
    }
  });
  it('does not tag unrelated names', () => {
    expect(computeTags({ type: 'input', subType: 'text', name: 'firstname' })).not.toContain(
      'redirect-param'
    );
  });
});

describe('computeTags - id-param (IDOR candidates)', () => {
  it('tags fields whose name suggests an object identifier', () => {
    for (const name of ['id', 'user_id', 'uid', 'account', 'account_id', 'order_id', 'doc_id', 'pid']) {
      expect(computeTags({ type: 'input', subType: 'text', name })).toContain('id-param');
    }
  });
  it('does not tag names that merely contain "id" as a substring of a word', () => {
    expect(computeTags({ type: 'input', subType: 'text', name: 'video' })).not.toContain('id-param');
    expect(computeTags({ type: 'input', subType: 'text', name: 'width' })).not.toContain('id-param');
  });
});

describe('computeTags - unvalidated', () => {
  it('tags text inputs that lack any client-side validation', () => {
    expect(computeTags({ type: 'input', subType: 'text', name: 'comment' })).toContain('unvalidated');
  });
  it('does not tag a text input that has a pattern', () => {
    expect(
      computeTags({ type: 'input', subType: 'text', name: 'comment', pattern: '[a-z]+' })
    ).not.toContain('unvalidated');
  });
  it('does not tag a text input that has a maxlength', () => {
    expect(
      computeTags({ type: 'input', subType: 'text', name: 'comment', maxlength: 50 })
    ).not.toContain('unvalidated');
  });
  it('does not tag non-text fields (select/file) as unvalidated', () => {
    expect(computeTags({ type: 'select', subType: 'select', name: 's' })).not.toContain('unvalidated');
    expect(computeTags({ type: 'file', subType: 'file', name: 'f' })).not.toContain('unvalidated');
  });
});

describe('computeTags - combinations & shape', () => {
  it('returns an array', () => {
    expect(Array.isArray(computeTags({ type: 'input', subType: 'text', name: 'x' }))).toBe(true);
  });
  it('can return multiple tags for one field', () => {
    const tags = computeTags({ subType: 'hidden', hidden: true, name: 'redirect_uri', value: '/' });
    expect(tags).toEqual(expect.arrayContaining(['hidden', 'redirect-param']));
  });
  it('does not emit duplicate tags', () => {
    const tags = computeTags({ type: 'input', subType: 'email', name: 'email' });
    const unique = new Set(tags);
    expect(unique.size).toBe(tags.length);
  });
  it('handles missing name gracefully', () => {
    expect(() => computeTags({ type: 'input', subType: 'text' })).not.toThrow();
  });
});
