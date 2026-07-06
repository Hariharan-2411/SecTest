import { describe, it, expect } from '@jest/globals';
import {
  emptyInventory,
  extractParamsFromUrls,
  mergeObservation,
  summarizeInventory,
} from '../src/utils/inventory';

describe('extractParamsFromUrls', () => {
  it('collects distinct param names, ignoring values', () => {
    const names = extractParamsFromUrls([
      'https://x.com/a?id=1&next=/home',
      'https://x.com/b?id=2&token=abc',
    ]);
    expect(names.sort()).toEqual(['id', 'next', 'token']);
  });
  it('handles relative urls with a query string', () => {
    expect(extractParamsFromUrls(['/search?q=hi'])).toEqual(['q']);
  });
});

describe('mergeObservation', () => {
  it('accumulates and de-duplicates across observations', () => {
    let inv = emptyInventory();
    inv = mergeObservation(
      inv,
      { pageUrl: 'https://x.com/1', endpoints: ['/api/a?id=1'], scripts: ['/app.js'] },
      '2026-01-01T00:00:00Z'
    );
    inv = mergeObservation(
      inv,
      { pageUrl: 'https://x.com/2', endpoints: ['/api/a?id=1', '/api/b'], scripts: ['/app.js'] },
      '2026-01-02T00:00:00Z'
    );
    expect(inv.endpoints.sort()).toEqual(['/api/a?id=1', '/api/b']);
    expect(inv.scripts).toEqual(['/app.js']);
    expect(inv.pages.sort()).toEqual(['https://x.com/1', 'https://x.com/2']);
    expect(inv.params).toEqual(['id']);
    expect(inv.firstSeen).toBe('2026-01-01T00:00:00Z');
    expect(inv.updatedAt).toBe('2026-01-02T00:00:00Z');
  });

  it('de-dupes forms by method+action', () => {
    const inv = mergeObservation(emptyInventory(), {
      pageUrl: 'https://x.com',
      forms: [
        { method: 'post', action: '/login', fieldCount: 2 },
        { method: 'POST', action: '/login', fieldCount: 2 },
      ],
    });
    expect(inv.forms.length).toBe(1);
  });
});

describe('cap boundary', () => {
  it('never exceeds the endpoint cap even across many observations', () => {
    let inv = emptyInventory();
    // Push well past the 1000 cap with unique two-segment paths.
    for (let batch = 0; batch < 3; batch++) {
      const endpoints = [];
      for (let i = 0; i < 500; i++) endpoints.push(`/api/x${batch}_${i}`);
      inv = mergeObservation(inv, { pageUrl: 'https://x.com', endpoints });
    }
    expect(inv.endpoints.length).toBeLessThanOrEqual(1000);
  });
  it('keeps already-seen items stable (dedup) below the cap', () => {
    let inv = mergeObservation(emptyInventory(), { pageUrl: 'https://x.com', endpoints: ['/api/a'] });
    inv = mergeObservation(inv, { pageUrl: 'https://x.com', endpoints: ['/api/a', '/api/a'] });
    expect(inv.endpoints).toEqual(['/api/a']);
  });
});

describe('summarizeInventory', () => {
  it('returns counts', () => {
    const inv = mergeObservation(emptyInventory(), {
      pageUrl: 'https://x.com',
      endpoints: ['/a', '/b'],
    });
    expect(summarizeInventory(inv)).toMatchObject({ endpoints: 2, pages: 1 });
  });
});
