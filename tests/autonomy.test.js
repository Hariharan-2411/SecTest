import { describe, it, expect } from '@jest/globals';
import { AUTONOMY_LEVELS, DEFAULT_AUTONOMY, decideAutonomy, autoTriggerEnabled } from '../src/utils/autonomy';

describe('autonomy levels', () => {
  it('exposes the three levels with a safe default', () => {
    expect(AUTONOMY_LEVELS).toEqual(['manual', 'assisted', 'auto-safe']);
    expect(DEFAULT_AUTONOMY).toBe('assisted');
  });
});

describe('decideAutonomy', () => {
  it('active steps ALWAYS gate, at every level (core guardrail)', () => {
    for (const level of AUTONOMY_LEVELS) {
      expect(decideAutonomy(level, 'active')).toBe('gate');
    }
  });

  it('manual gates even safe steps (human triggers everything)', () => {
    expect(decideAutonomy('manual', 'safe')).toBe('gate');
  });

  it('assisted and auto-safe auto-run safe steps', () => {
    expect(decideAutonomy('assisted', 'safe')).toBe('run');
    expect(decideAutonomy('auto-safe', 'safe')).toBe('run');
  });

  it('non-executable risks (none/manual/unknown) skip', () => {
    expect(decideAutonomy('auto-safe', 'none')).toBe('skip');
    expect(decideAutonomy('assisted', 'manual')).toBe('skip');
    expect(decideAutonomy('assisted', 'whatever')).toBe('skip');
  });

  it('falls back to the default level for an unknown level', () => {
    // unknown level behaves like 'assisted'
    expect(decideAutonomy('bogus', 'safe')).toBe('run');
    expect(decideAutonomy(undefined, 'active')).toBe('gate');
  });
});

describe('autoTriggerEnabled', () => {
  it('only auto-safe auto-initiates the safe part of a suggestion', () => {
    expect(autoTriggerEnabled('auto-safe')).toBe(true);
    expect(autoTriggerEnabled('assisted')).toBe(false);
    expect(autoTriggerEnabled('manual')).toBe(false);
    expect(autoTriggerEnabled('bogus')).toBe(false);
  });
});
