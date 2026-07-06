import { describe, it, expect } from '@jest/globals';
import {
  hashText,
  findSecrets,
  makeSnapshot,
  diffSnapshots,
  isInterestingDiff,
  summarizeDiff,
} from '../src/utils/jsdiff';

describe('hashText', () => {
  it('is stable and content-sensitive', () => {
    expect(hashText('abc')).toBe(hashText('abc'));
    expect(hashText('abc')).not.toBe(hashText('abd'));
  });
});

describe('findSecrets', () => {
  it('detects and masks an AWS key', () => {
    const res = findSecrets('const k = "AKIAIOSFODNN7EXAMPLE";');
    expect(res).toEqual([{ type: 'aws_access_key', preview: 'AKIA…MPLE' }]);
  });
  it('never returns the raw secret', () => {
    const raw = 'AKIAIOSFODNN7EXAMPLE';
    const res = findSecrets(raw);
    expect(res[0].preview).not.toBe(raw);
  });
  it('returns nothing for clean text', () => {
    expect(findSecrets('let x = 1;')).toEqual([]);
  });
});

describe('makeSnapshot', () => {
  it('captures hash, endpoints and secrets', () => {
    const snap = makeSnapshot(
      'https://x.com/app.js',
      'fetch("/api/users"); var t="AKIAIOSFODNN7EXAMPLE";',
      '2026-01-01T00:00:00Z'
    );
    expect(snap.url).toBe('https://x.com/app.js');
    expect(snap.endpoints).toContain('/api/users');
    expect(snap.secrets.length).toBe(1);
    expect(snap.capturedAt).toBe('2026-01-01T00:00:00Z');
  });
});

describe('diffSnapshots', () => {
  it('treats a first sighting as new with all endpoints added', () => {
    const next = makeSnapshot('u', 'fetch("/api/a")');
    const d = diffSnapshots(null, next);
    expect(d.isNew).toBe(true);
    expect(d.addedEndpoints).toContain('/api/a');
  });

  it('detects added and removed endpoints between versions', () => {
    const prev = makeSnapshot('u', 'fetch("/api/a"); fetch("/api/b")');
    const next = makeSnapshot('u', 'fetch("/api/a"); fetch("/api/c")');
    const d = diffSnapshots(prev, next);
    expect(d.isNew).toBe(false);
    expect(d.changed).toBe(true);
    expect(d.addedEndpoints).toContain('/api/c');
    expect(d.removedEndpoints).toContain('/api/b');
  });

  it('flags newly introduced secrets only', () => {
    const prev = makeSnapshot('u', 'var a=1;');
    const next = makeSnapshot('u', 'var k="AKIAIOSFODNN7EXAMPLE";');
    const d = diffSnapshots(prev, next);
    expect(d.newSecrets.length).toBe(1);
  });

  it('reports no change when content is identical', () => {
    const prev = makeSnapshot('u', 'same');
    const next = makeSnapshot('u', 'same');
    expect(diffSnapshots(prev, next).changed).toBe(false);
  });

  it('returns a safe empty guard when next is null', () => {
    const d = diffSnapshots(makeSnapshot('u', 'x'), null);
    expect(d).toMatchObject({ isNew: false, changed: false, addedEndpoints: [], newSecrets: [] });
  });
});

describe('isInterestingDiff / summarizeDiff', () => {
  it('interesting when endpoints added', () => {
    const prev = makeSnapshot('u', 'fetch("/api/a")');
    const next = makeSnapshot('u', 'fetch("/api/a"); fetch("/api/b")');
    const d = diffSnapshots(prev, next);
    expect(isInterestingDiff(d)).toBe(true);
    expect(summarizeDiff(d)).toContain('+1 endpoint');
  });
  it('not interesting when only removals', () => {
    const prev = makeSnapshot('u', 'fetch("/api/a"); fetch("/api/b")');
    const next = makeSnapshot('u', 'fetch("/api/a")');
    const d = diffSnapshots(prev, next);
    expect(isInterestingDiff(d)).toBe(false);
  });
});
