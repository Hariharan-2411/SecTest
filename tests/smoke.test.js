// Smoke test: proves the Jest + jsdom + babel (ESM) toolchain works.
import { describe, it, expect } from '@jest/globals';

describe('test harness', () => {
  it('runs jest', () => {
    expect(1 + 1).toBe(2);
  });

  it('has a jsdom document', () => {
    document.body.innerHTML = '<input id="x" type="text" />';
    const el = document.getElementById('x');
    expect(el).not.toBeNull();
    expect(el.type).toBe('text');
  });
});
