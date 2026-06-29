import { describe, it, expect, beforeEach } from '@jest/globals';
import { collectFields } from '../src/utils/extraction';

function setBody(html) {
  document.body.innerHTML = html;
}

describe('collectFields - light DOM', () => {
  beforeEach(() => setBody(''));

  it('finds inputs, textareas, selects and file inputs', () => {
    setBody(`
      <input name="a" type="text">
      <textarea name="b"></textarea>
      <select name="c"><option value="x">x</option></select>
      <input name="d" type="file">
    `);
    const { fields } = collectFields(document.body);
    const names = fields.map((f) => f.name).sort();
    expect(names).toEqual(['a', 'b', 'c', 'd']);
  });

  it('includes contenteditable elements', () => {
    setBody('<div name="rt" contenteditable="true">hi</div>');
    const { fields } = collectFields(document.body);
    expect(fields.some((f) => f.type === 'contenteditable')).toBe(true);
  });

  it('returns rich metadata (tags) on each field', () => {
    setBody('<input name="csrf_token" type="hidden" value="x">');
    const { fields } = collectFields(document.body);
    expect(fields[0].tags).toEqual(expect.arrayContaining(['hidden', 'csrf-token']));
  });

  it('assigns a unique id to each field', () => {
    setBody('<input name="a" type="text"><input name="b" type="text">');
    const { fields } = collectFields(document.body);
    const ids = fields.map((f) => f.uniqueId);
    expect(new Set(ids).size).toBe(2);
    expect(ids.every(Boolean)).toBe(true);
  });

  it('reports zero unscannable contexts for a plain page', () => {
    setBody('<input name="a" type="text">');
    const { unscannable } = collectFields(document.body);
    expect(unscannable.crossOriginFrames).toBe(0);
  });
});

describe('collectFields - open shadow DOM', () => {
  beforeEach(() => setBody(''));

  it('descends into an open shadow root', () => {
    setBody('<div id="host"></div>');
    const host = document.getElementById('host');
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = '<input name="shadow_field" type="text">';

    const { fields } = collectFields(document.body);
    expect(fields.some((f) => f.name === 'shadow_field')).toBe(true);
  });

  it('descends into nested shadow roots', () => {
    setBody('<div id="host"></div>');
    const host = document.getElementById('host');
    const outer = host.attachShadow({ mode: 'open' });
    const innerHost = document.createElement('div');
    outer.appendChild(innerHost);
    const inner = innerHost.attachShadow({ mode: 'open' });
    inner.innerHTML = '<input name="deep_field" type="text">';

    const { fields } = collectFields(document.body);
    expect(fields.some((f) => f.name === 'deep_field')).toBe(true);
  });

  it('marks shadow-hosted fields with a context note', () => {
    setBody('<div id="host"></div>');
    const shadow = document.getElementById('host').attachShadow({ mode: 'open' });
    shadow.innerHTML = '<input name="sf" type="text">';

    const { fields } = collectFields(document.body);
    const f = fields.find((x) => x.name === 'sf');
    expect(f.context).toBe('shadow');
  });
});

describe('collectFields - closed shadow DOM', () => {
  beforeEach(() => setBody(''));

  it('does not read fields inside a closed shadow root', () => {
    // Closed shadow roots are not observable from script (host.shadowRoot is
    // null, with no internals exposed) — this is true in real browsers too,
    // so we simply cannot reach their fields. We assert we never leak them.
    setBody('<div id="host"></div>');
    const host = document.getElementById('host');
    const closed = host.attachShadow({ mode: 'closed' });
    closed.innerHTML = '<input name="secret" type="text">';

    const { fields } = collectFields(document.body);
    expect(fields.some((f) => f.name === 'secret')).toBe(false);
  });
});

describe('collectFields - iframes', () => {
  beforeEach(() => setBody(''));

  it('descends into a same-origin iframe', () => {
    setBody('<iframe id="f"></iframe>');
    const iframe = document.getElementById('f');
    const doc = iframe.contentDocument;
    doc.body.innerHTML = '<input name="frame_field" type="text">';

    const { fields } = collectFields(document.body);
    expect(fields.some((x) => x.name === 'frame_field')).toBe(true);
  });

  it('marks iframe-hosted fields with a context note', () => {
    setBody('<iframe id="f"></iframe>');
    document.getElementById('f').contentDocument.body.innerHTML =
      '<input name="ff" type="text">';
    const { fields } = collectFields(document.body);
    const f = fields.find((x) => x.name === 'ff');
    expect(f.context).toBe('iframe');
  });

  it('counts a cross-origin iframe as unscannable without throwing', () => {
    setBody('<iframe id="f"></iframe>');
    const iframe = document.getElementById('f');
    // Simulate a cross-origin frame: accessing contentDocument throws.
    Object.defineProperty(iframe, 'contentDocument', {
      get() {
        throw new DOMException('blocked', 'SecurityError');
      },
    });

    let result;
    expect(() => {
      result = collectFields(document.body);
    }).not.toThrow();
    expect(result.unscannable.crossOriginFrames).toBe(1);
  });
});

describe('collectFields - shape', () => {
  it('returns an object with fields[] and unscannable counts', () => {
    document.body.innerHTML = '<input name="a" type="text">';
    const result = collectFields(document.body);
    expect(result).toHaveProperty('fields');
    expect(Array.isArray(result.fields)).toBe(true);
    expect(result).toHaveProperty('unscannable');
    expect(result.unscannable).toMatchObject({
      crossOriginFrames: expect.any(Number),
    });
  });
});
