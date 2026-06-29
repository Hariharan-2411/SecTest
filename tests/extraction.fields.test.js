import { describe, it, expect, beforeEach } from '@jest/globals';
import { extractFieldMetadata, resolveLabel } from '../src/utils/extraction';

function setBody(html) {
  document.body.innerHTML = html;
}

describe('resolveLabel', () => {
  beforeEach(() => setBody(''));

  it('resolves a <label for> association', () => {
    setBody('<label for="u">Username</label><input id="u" type="text">');
    const el = document.getElementById('u');
    expect(resolveLabel(el)).toBe('Username');
  });

  it('resolves a wrapping label', () => {
    setBody('<label>Email <input id="e" type="email"></label>');
    const el = document.getElementById('e');
    expect(resolveLabel(el)).toBe('Email');
  });

  it('falls back to aria-label', () => {
    setBody('<input id="s" type="search" aria-label="Site search">');
    const el = document.getElementById('s');
    expect(resolveLabel(el)).toBe('Site search');
  });

  it('falls back to placeholder when nothing else exists', () => {
    setBody('<input id="p" type="text" placeholder="Type here">');
    const el = document.getElementById('p');
    expect(resolveLabel(el)).toBe('Type here');
  });

  it('returns empty string when no label source exists', () => {
    setBody('<input id="n" type="text">');
    const el = document.getElementById('n');
    expect(resolveLabel(el)).toBe('');
  });

  it('prefers explicit <label for> over aria-label and placeholder', () => {
    setBody(
      '<label for="x">Real Label</label><input id="x" type="text" aria-label="aria" placeholder="ph">'
    );
    const el = document.getElementById('x');
    expect(resolveLabel(el)).toBe('Real Label');
  });
});

describe('extractFieldMetadata - core attributes', () => {
  beforeEach(() => setBody(''));

  it('captures basic input attributes', () => {
    setBody(
      '<input id="user" name="username" type="text" placeholder="Name" value="bob" required>'
    );
    const meta = extractFieldMetadata(document.getElementById('user'));
    expect(meta).toMatchObject({
      type: 'input',
      subType: 'text',
      name: 'username',
      id: 'user',
      placeholder: 'Name',
      value: 'bob',
      required: true,
    });
  });

  it('defaults subType to text for an input with no type', () => {
    setBody('<input id="x" name="x">');
    const meta = extractFieldMetadata(document.getElementById('x'));
    expect(meta.subType).toBe('text');
  });

  it('captures textarea as its own type', () => {
    setBody('<textarea id="c" name="comment">hi</textarea>');
    const meta = extractFieldMetadata(document.getElementById('c'));
    expect(meta.type).toBe('textarea');
    expect(meta.subType).toBe('textarea');
    expect(meta.value).toBe('hi');
  });

  it('captures select with options and selected value', () => {
    setBody(
      '<select id="ctry" name="country"><option value="us">US</option><option value="ca" selected>CA</option></select>'
    );
    const meta = extractFieldMetadata(document.getElementById('ctry'));
    expect(meta.type).toBe('select');
    expect(meta.options).toEqual(['us', 'ca']);
    expect(meta.selectedValue).toBe('ca');
  });

  it('captures file input accept and multiple', () => {
    setBody('<input id="f" name="doc" type="file" accept="image/*" multiple>');
    const meta = extractFieldMetadata(document.getElementById('f'));
    expect(meta.type).toBe('file');
    expect(meta.subType).toBe('file');
    expect(meta.accept).toBe('image/*');
    expect(meta.multiple).toBe(true);
  });

  it('treats a contenteditable element as a field', () => {
    setBody('<div id="rt" contenteditable="true">rich text</div>');
    const meta = extractFieldMetadata(document.getElementById('rt'));
    expect(meta.type).toBe('contenteditable');
    expect(meta.value).toBe('rich text');
  });
});

describe('extractFieldMetadata - validation constraints', () => {
  beforeEach(() => setBody(''));

  it('captures text constraints (maxlength, minlength, pattern, autocomplete)', () => {
    setBody(
      '<input id="t" name="t" type="text" maxlength="10" minlength="2" pattern="[a-z]+" autocomplete="off">'
    );
    const meta = extractFieldMetadata(document.getElementById('t'));
    expect(meta.maxlength).toBe(10);
    expect(meta.minlength).toBe(2);
    expect(meta.pattern).toBe('[a-z]+');
    expect(meta.autocomplete).toBe('off');
  });

  it('captures numeric constraints (min, max, step)', () => {
    setBody('<input id="n" name="n" type="number" min="1" max="100" step="5">');
    const meta = extractFieldMetadata(document.getElementById('n'));
    expect(meta.min).toBe('1');
    expect(meta.max).toBe('100');
    expect(meta.step).toBe('5');
  });

  it('omits unset constraints rather than emitting nulls', () => {
    setBody('<input id="p" name="p" type="text">');
    const meta = extractFieldMetadata(document.getElementById('p'));
    expect(meta.maxlength).toBeUndefined();
    expect(meta.pattern).toBeUndefined();
  });
});

describe('extractFieldMetadata - state flags', () => {
  beforeEach(() => setBody(''));

  it('captures readonly and disabled', () => {
    setBody('<input id="r" name="r" type="text" readonly disabled>');
    const meta = extractFieldMetadata(document.getElementById('r'));
    expect(meta.readonly).toBe(true);
    expect(meta.disabled).toBe(true);
  });

  it('flags type=hidden inputs', () => {
    setBody('<input id="h" name="csrf" type="hidden" value="abc123">');
    const meta = extractFieldMetadata(document.getElementById('h'));
    expect(meta.subType).toBe('hidden');
    expect(meta.hidden).toBe(true);
  });

  it('flags elements hidden via the hidden attribute', () => {
    setBody('<input id="h2" name="x" type="text" hidden>');
    const meta = extractFieldMetadata(document.getElementById('h2'));
    expect(meta.hidden).toBe(true);
  });

  it('does not flag a visible text input as hidden', () => {
    setBody('<input id="v" name="x" type="text">');
    const meta = extractFieldMetadata(document.getElementById('v'));
    expect(meta.hidden).toBe(false);
  });
});

describe('extractFieldMetadata - form association', () => {
  beforeEach(() => setBody(''));

  it('captures owning form action, method and enctype', () => {
    setBody(
      '<form action="/login" method="post" enctype="multipart/form-data"><input id="u" name="u" type="text"></form>'
    );
    const meta = extractFieldMetadata(document.getElementById('u'));
    expect(meta.formAction).toBe('/login');
    expect(meta.formMethod).toBe('post');
    expect(meta.formEnctype).toBe('multipart/form-data');
  });

  it('defaults form method to get when unspecified', () => {
    setBody('<form action="/search"><input id="q" name="q" type="search"></form>');
    const meta = extractFieldMetadata(document.getElementById('q'));
    expect(meta.formMethod).toBe('get');
  });

  it('leaves form fields undefined for an input outside any form', () => {
    setBody('<input id="loose" name="loose" type="text">');
    const meta = extractFieldMetadata(document.getElementById('loose'));
    expect(meta.formAction).toBeUndefined();
    expect(meta.formMethod).toBeUndefined();
  });

  it('resolves and attaches the label', () => {
    setBody('<form><label for="u">User Name</label><input id="u" name="u" type="text"></form>');
    const meta = extractFieldMetadata(document.getElementById('u'));
    expect(meta.label).toBe('User Name');
  });
});

describe('extractFieldMetadata - tags integration', () => {
  beforeEach(() => setBody(''));

  it('attaches a tags array computed from the metadata', () => {
    setBody('<input id="h" name="csrf_token" type="hidden" value="abc">');
    const meta = extractFieldMetadata(document.getElementById('h'));
    expect(Array.isArray(meta.tags)).toBe(true);
    expect(meta.tags).toEqual(expect.arrayContaining(['hidden', 'csrf-token']));
  });

  it('tags a file input as file-upload', () => {
    setBody('<input id="f" name="doc" type="file">');
    const meta = extractFieldMetadata(document.getElementById('f'));
    expect(meta.tags).toContain('file-upload');
  });
});
