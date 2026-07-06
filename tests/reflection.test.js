import { describe, it, expect } from '@jest/globals';
import {
  classifyReflection,
  summarizeReflection,
  makeMarker,
} from '../src/utils/reflection';

const M = 'zqxABC123rfl';

describe('classifyReflection', () => {
  it('detects html-body context', () => {
    const r = classifyReflection(`<div>hello ${M} world</div>`, M);
    expect(r.contexts).toEqual(['html-body']);
    expect(r.count).toBe(1);
  });

  it('detects attribute context', () => {
    const r = classifyReflection(`<input value="${M}">`, M);
    expect(r.contexts).toContain('attribute');
  });

  it('detects js context inside a script block', () => {
    const r = classifyReflection(`<script>var x = "${M}";</script>`, M);
    expect(r.contexts).toContain('js');
  });

  it('finds multiple contexts and counts all hits', () => {
    const html = `<div>${M}</div><img alt="${M}"><script>y="${M}"</script>`;
    const r = classifyReflection(html, M);
    expect(r.count).toBe(3);
    expect(r.contexts.sort()).toEqual(['attribute', 'html-body', 'js']);
  });

  it('returns empty when the marker is absent', () => {
    expect(classifyReflection('<div>nothing here</div>', M)).toEqual({ contexts: [], count: 0 });
  });

  it('handles bad input safely', () => {
    expect(classifyReflection(null, M)).toEqual({ contexts: [], count: 0 });
    expect(classifyReflection('<div>x</div>', '')).toEqual({ contexts: [], count: 0 });
  });
});

describe('summarizeReflection', () => {
  it('reports not reflected on a clean page', () => {
    expect(summarizeReflection('<div>clean</div>', M)).toEqual({ reflected: false, contexts: [], count: 0 });
  });

  it('adds url context when urlReflected is set', () => {
    const r = summarizeReflection('<div>clean</div>', M, { urlReflected: true });
    expect(r.reflected).toBe(true);
    expect(r.contexts).toContain('url');
  });

  it('merges DOM and url contexts', () => {
    const r = summarizeReflection(`<div>${M}</div>`, M, { urlReflected: true });
    expect(r.contexts.sort()).toEqual(['html-body', 'url']);
  });
});

describe('makeMarker', () => {
  it('produces a unique, searchable token', () => {
    const a = makeMarker();
    const b = makeMarker();
    expect(a).toMatch(/^zqx[a-z0-9]+rfl$/);
    expect(a).not.toBe(b);
  });
});
