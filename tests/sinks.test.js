import { describe, it, expect } from '@jest/globals';
import { mapSinks, isTaintedSink } from '../src/utils/sinks';

describe('mapSinks — sink detection', () => {
  it('detects innerHTML assignment', () => {
    const res = mapSinks('el.innerHTML = "hi";');
    expect(res).toHaveLength(1);
    expect(res[0].sink).toBe('innerHTML');
    expect(res[0].line).toBe(1);
  });

  it('detects document.write, eval, and insertAdjacentHTML', () => {
    const src = [
      'document.write(x);',
      'eval(code);',
      'node.insertAdjacentHTML("beforeend", y);',
    ].join('\n');
    const sinks = mapSinks(src).map((s) => s.sink);
    expect(sinks).toContain('document.write');
    expect(sinks).toContain('eval');
    expect(sinks).toContain('insertAdjacentHTML');
  });

  it('returns nothing for clean code', () => {
    expect(mapSinks('const a = 1 + 2;')).toEqual([]);
  });

  it('handles non-string input safely', () => {
    expect(mapSinks(null)).toEqual([]);
    expect(mapSinks(undefined)).toEqual([]);
  });
});

describe('mapSinks — source proximity (taint candidates)', () => {
  it('flags a source on the same line as a sink', () => {
    const res = mapSinks('el.innerHTML = location.hash;');
    expect(res[0].sources).toContain('location');
    expect(isTaintedSink(res[0])).toBe(true);
  });

  it('flags a source within a couple of lines', () => {
    const src = [
      'const data = document.referrer;',
      '// process',
      'container.innerHTML = data;',
    ].join('\n');
    const entry = mapSinks(src).find((s) => s.sink === 'innerHTML');
    expect(entry.sources).toContain('referrer');
    expect(isTaintedSink(entry)).toBe(true);
  });

  it('detects postMessage handler data as a source', () => {
    const src = 'window.addEventListener("message", (e) => { box.innerHTML = e.data; });';
    const entry = mapSinks(src)[0];
    expect(entry.sources).toContain('postMessage');
  });

  it('does not mark a sink tainted when no source is near', () => {
    const entry = mapSinks('el.innerHTML = "<b>static</b>";')[0];
    expect(entry.sources).toEqual([]);
    expect(isTaintedSink(entry)).toBe(false);
  });
});
