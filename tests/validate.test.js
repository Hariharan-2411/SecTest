import { describe, it, expect } from '@jest/globals';
import {
  scoreFinding,
  validateFinding,
  validateFindings,
  filterForReport,
  canEscalateFinding,
  bandFor,
  BANDS,
  DEFAULT_REPORT_THRESHOLD,
  RULES,
} from '../src/utils/validate';
import { ACTION_VERBS } from '../src/utils/escalation';

describe('bandFor — band boundaries', () => {
  it('maps confidence onto the four bands at the exact boundaries', () => {
    expect(bandFor(80)).toBe('confirmed');
    expect(bandFor(79)).toBe('likely');
    expect(bandFor(55)).toBe('likely');
    expect(bandFor(54)).toBe('tentative');
    expect(bandFor(30)).toBe('tentative');
    expect(bandFor(29)).toBe('noise');
    expect(bandFor(0)).toBe('noise');
  });
});

describe('scoreFinding — dom-xss / reflection', () => {
  it('executed context + tainted sink clamps at 100 (confirmed)', () => {
    const r = scoreFinding({
      type: 'dom-xss',
      reflection: 'js',
      sink: 'innerHTML',
      sources: ['location.hash'],
    });
    expect(r.confidence).toBe(100); // 30 + 50 + 25 = 105 -> clamp 100
    expect(r.band).toBe('confirmed');
  });

  it('executed context without a sink lands exactly on the confirmed floor (80)', () => {
    const r = scoreFinding({ type: 'dom-xss', reflection: 'js' });
    expect(r.confidence).toBe(80);
    expect(r.band).toBe('confirmed');
  });

  it('html-body context without a sink is likely (75)', () => {
    const r = scoreFinding({ type: 'dom-xss', reflection: 'html-body' });
    expect(r.confidence).toBe(75);
    expect(r.band).toBe('likely');
  });

  it('attribute context is tentative and asks to confirm reflection', () => {
    const r = scoreFinding({ type: 'dom-xss', reflection: 'attribute' });
    expect(r.confidence).toBe(45); // 30 + 15
    expect(r.band).toBe('tentative');
    expect(r.needMore).toContain('confirm_reflection');
  });

  it('no-reflection context clamps at 0 (noise)', () => {
    const r = scoreFinding({ type: 'dom-xss', reflection: 'none' });
    expect(r.confidence).toBe(0); // 30 - 35 = -5 -> clamp 0
    expect(r.band).toBe('noise');
  });

  it('missing reflection evidence stays tentative and asks to confirm reflection', () => {
    const r = scoreFinding({ type: 'dom-xss' });
    expect(r.confidence).toBe(30);
    expect(r.needMore).toContain('confirm_reflection');
  });

  it('a real taint finding (source->sink, no reflection field) is likely', () => {
    const r = scoreFinding({
      type: 'dom-xss',
      sink: 'innerHTML',
      sources: ['location.hash'],
    });
    expect(r.confidence).toBe(55); // 30 + 25 tainted-sink bonus
    expect(r.band).toBe('likely');
    // The sink flow is the evidence — don't nag to confirm reflection.
    expect(r.needMore).not.toContain('confirm_reflection');
  });
});

describe('scoreFinding — injection oracles (real sqli-* types)', () => {
  it('a boolean-based differential is confirmed (80)', () => {
    expect(scoreFinding({ type: 'sqli-boolean' }).confidence).toBe(80);
    expect(scoreFinding({ type: 'sqli-boolean' }).band).toBe('confirmed');
  });

  it('a time-based signal is likely, flags timing noise, and asks for a differential probe', () => {
    const r = scoreFinding({ type: 'sqli-time' });
    expect(r.confidence).toBe(65); // 30 + 35
    expect(r.band).toBe('likely');
    expect(r.needMore).toContain('differential_probe');
    expect(r.reasons.join(' ')).toMatch(/nois/i);
  });
});

describe('scoreFinding — secrets', () => {
  it('a pattern-anchored key with high entropy is confirmed', () => {
    const r = scoreFinding({ type: 'aws_access_key', entropy: 4.5 });
    expect(r.confidence).toBe(86); // 78 + 8
    expect(r.band).toBe('confirmed');
  });

  it('the same key without entropy evidence is only likely', () => {
    expect(scoreFinding({ type: 'aws_access_key' }).confidence).toBe(78);
  });

  it('never certifies a secret as fully certain — the cap holds', () => {
    const r = scoreFinding({ type: 'private_key', entropy: 4.5 });
    expect(r.confidence).toBe(RULES.secretCap); // 85 + 8 = 93 -> capped 90
    expect(r.confidence).toBeLessThanOrEqual(RULES.secretCap);
  });

  it('a low-entropy jwt is penalized as a likely placeholder', () => {
    const r = scoreFinding({ type: 'jwt', entropy: 2.5 });
    expect(r.confidence).toBe(35); // 50 - 15
    expect(r.band).toBe('tentative');
  });
});

describe('scoreFinding — oob and headers', () => {
  it('a received out-of-band callback is confirmed', () => {
    const r = scoreFinding({ type: 'oob', oobHit: true });
    expect(r.confidence).toBe(95); // 40 + 55
    expect(r.band).toBe('confirmed');
  });

  it('an oob finding with no callback stays tentative', () => {
    const r = scoreFinding({ type: 'oob', oobHit: false });
    expect(r.confidence).toBe(40);
    expect(r.band).toBe('tentative');
  });

  it('a header finding is low and can never exceed the header cap', () => {
    const r = scoreFinding({ type: 'header' });
    expect(r.confidence).toBe(35);
    expect(r.confidence).toBeLessThanOrEqual(RULES.headersCap);
    expect(r.band).toBe('tentative');
  });

  it('a nuclei template match scores as likely (high-signal, human-verified)', () => {
    const r = scoreFinding({ type: 'nuclei', severity: 'critical' });
    expect(r.confidence).toBe(75);
    expect(r.band).toBe('likely');
  });
});

describe('scoreFinding — safety & purity', () => {
  it('an unknown type degrades to a safe tentative default without throwing', () => {
    const r = scoreFinding({ type: 'quantum_bug' });
    expect(r.band).toBe('tentative');
    expect(r.needMore).toContain('manual');
  });

  it('ignores and recomputes a caller-supplied confidence (never trust the input)', () => {
    const r = scoreFinding({
      type: 'dom-xss',
      reflection: 'attribute',
      confidence: 999,
    });
    expect(r.confidence).toBe(45);
  });

  it('always returns a confidence within 0..100', () => {
    for (const f of [
      { type: 'dom-xss', reflection: 'js', sink: 'eval', sources: ['x'] },
      { type: 'dom-xss', reflection: 'none' },
      { type: 'sqli-boolean' },
    ]) {
      const c = scoreFinding(f).confidence;
      expect(c).toBeGreaterThanOrEqual(0);
      expect(c).toBeLessThanOrEqual(100);
    }
  });

  it('every suggested needMore verb is a real escalation verb', () => {
    const verbs = new Set(Object.keys(ACTION_VERBS));
    const samples = [
      { type: 'dom-xss', reflection: 'attribute' },
      { type: 'sqli-time' },
      { type: 'oob', oobHit: false },
      { type: 'quantum_bug' },
    ];
    for (const s of samples) {
      for (const v of scoreFinding(s).needMore) expect(verbs.has(v)).toBe(true);
    }
  });
});

describe('validateFinding — annotation without mutation', () => {
  it('returns a new finding carrying .validation and a normalized top-level .confidence', () => {
    const input = { type: 'dom-xss', reflection: 'js', confidence: null };
    const out = validateFinding(input);
    expect(out).not.toBe(input);
    expect(out.validation.confidence).toBe(80);
    expect(out.validation.band).toBe('confirmed');
    expect(out.confidence).toBe(80);
  });

  it('does not mutate the input finding', () => {
    const input = { type: 'dom-xss', reflection: 'attribute', confidence: 7 };
    validateFinding(input);
    expect(input.validation).toBeUndefined();
    expect(input.confidence).toBe(7);
  });

  it('validateFindings maps a list and tolerates a non-array', () => {
    const out = validateFindings([
      { type: 'sqli-boolean' },
      { type: 'header' },
    ]);
    expect(out).toHaveLength(2);
    expect(out[0].validation.band).toBe('confirmed');
    expect(validateFindings(null)).toEqual([]);
  });
});

describe('filterForReport — threshold gate', () => {
  it('keeps findings at or above the default report threshold and drops the rest', () => {
    const findings = [
      { type: 'sqli-boolean' }, // 80 - kept
      { type: 'sqli-time' }, // 65 - kept
      { type: 'dom-xss', reflection: 'attribute' }, // 45 - dropped
      { type: 'header' }, // 35 - dropped
    ];
    const kept = filterForReport(findings);
    expect(kept).toHaveLength(2);
    expect(DEFAULT_REPORT_THRESHOLD).toBe(BANDS.likely);
  });

  it('honors a custom minConfidence', () => {
    const findings = [{ type: 'dom-xss', reflection: 'attribute' }]; // 45
    expect(filterForReport(findings, { minConfidence: 40 })).toHaveLength(1);
    expect(filterForReport(findings, { minConfidence: 50 })).toHaveLength(0);
  });
});

describe('canEscalateFinding — band gate', () => {
  it('allows escalation at or above the minimum band, blocks below it', () => {
    expect(canEscalateFinding({ type: 'sqli-boolean' })).toBe(true); // confirmed
    expect(canEscalateFinding({ type: 'sqli-time' })).toBe(true); // likely
    expect(
      canEscalateFinding({ type: 'dom-xss', reflection: 'attribute' })
    ).toBe(false); // tentative
  });

  it('respects a custom minBand', () => {
    expect(
      canEscalateFinding({ type: 'sqli-time' }, { minBand: 'confirmed' })
    ).toBe(false);
    expect(
      canEscalateFinding(
        { type: 'dom-xss', reflection: 'attribute' },
        { minBand: 'tentative' }
      )
    ).toBe(true);
  });
});
