import { describe, it, expect } from '@jest/globals';
import {
  normalizeStep,
  normalizePlan,
  mapStepToAction,
  isSafeStep,
  canEscalate,
  remainingBudget,
  ACTION_VERBS,
  MAX_STEPS,
  MAX_DEPTH,
  DEFAULT_ESCALATION_BUDGET,
} from '../src/utils/escalation';

const scope = { inScope: ['*.example.com', 'example.com'], outOfScope: ['admin.example.com'] };
const ctx = { scope, host: 'example.com' };

describe('normalizeStep — allowlist & risk', () => {
  it('accepts an allow-listed safe verb and recomputes risk', () => {
    const s = normalizeStep({ type: 'deep_js', risk: 'active' /* lie */ }, ctx);
    expect(s.type).toBe('deep_js');
    expect(s.risk).toBe('safe'); // recomputed from the verb, model's claim ignored
  });

  it('downgrades an unknown verb to a manual note with reason', () => {
    const s = normalizeStep({ type: 'exfiltrate_db', rationale: 'dump users' }, ctx);
    expect(s.type).toBe('manual');
    expect(s.reason).toMatch(/unknown_verb/);
    expect(s.note).toBe('dump users');
  });

  it('tags agent_scan risk from the tool', () => {
    expect(normalizeStep({ type: 'agent_scan', tool: 'subfinder', target: 'example.com' }, ctx).risk).toBe('safe');
    expect(normalizeStep({ type: 'agent_scan', tool: 'nuclei', target: 'example.com' }, ctx).risk).toBe('active');
  });
});

describe('normalizeStep — scope enforcement', () => {
  it('accepts an in-scope url target', () => {
    const s = normalizeStep({ type: 'probe_endpoint', target: 'https://app.example.com/a' }, ctx);
    expect(s.type).toBe('probe_endpoint');
    expect(s.target).toBe('https://app.example.com/a');
  });

  it('downgrades an out-of-scope target to manual', () => {
    const s = normalizeStep({ type: 'differential_probe', target: 'https://evil.com/?id=1' }, ctx);
    expect(s.type).toBe('manual');
    expect(s.reason).toMatch(/out_of_scope/);
  });

  it('downgrades the explicitly out-of-scope carve-out', () => {
    const s = normalizeStep({ type: 'probe_endpoint', target: 'https://admin.example.com/x' }, ctx);
    expect(s.type).toBe('manual');
    expect(s.reason).toMatch(/out_of_scope/);
  });

  it('resolves a bare host to a scope-checked host target for agent_scan', () => {
    const s = normalizeStep({ type: 'agent_scan', tool: 'httpx', target: 'app.example.com' }, ctx);
    expect(s.type).toBe('agent_scan');
    expect(s.target).toBe('app.example.com');
  });

  it('rejects a missing/bad target for a targeted verb', () => {
    const s = normalizeStep({ type: 'probe_endpoint' }, ctx);
    expect(s.type).toBe('manual');
    expect(s.reason).toBe('bad_target');
  });

  it('does not require a target for current-page verbs', () => {
    const s = normalizeStep({ type: 'confirm_reflection' }, ctx);
    expect(s.type).toBe('confirm_reflection');
    expect(s.target).toBeUndefined();
  });
});

describe('normalizeStep — run_payload family gate', () => {
  it('accepts a known family', () => {
    expect(normalizeStep({ type: 'run_payload', payloadFamily: 'sqli' }, ctx).type).toBe('run_payload');
  });
  it('downgrades an unknown family to manual', () => {
    const s = normalizeStep({ type: 'run_payload', payloadFamily: 'deserialization' }, ctx);
    expect(s.type).toBe('manual');
    expect(s.reason).toMatch(/unknown_family/);
  });
});

describe('normalizePlan', () => {
  it('accepts {steps:[…]} and an array', () => {
    expect(normalizePlan({ steps: [{ type: 'deep_js' }] }, ctx).steps).toHaveLength(1);
    expect(normalizePlan([{ type: 'deep_js' }], ctx).steps).toHaveLength(1);
  });

  it('caps the step count and rejects the overflow', () => {
    const many = Array.from({ length: MAX_STEPS + 3 }, () => ({ type: 'deep_js' }));
    const { steps, rejected } = normalizePlan(many, ctx);
    expect(steps).toHaveLength(MAX_STEPS);
    expect(rejected).toHaveLength(3);
    expect(rejected[0].reason).toBe('over_cap');
  });

  it('handles garbage input safely', () => {
    expect(normalizePlan(null, ctx)).toEqual({ steps: [], rejected: [] });
    expect(normalizePlan({}, ctx)).toEqual({ steps: [], rejected: [] });
  });
});

describe('mapStepToAction', () => {
  it('maps each executable verb to an engine message', () => {
    expect(mapStepToAction({ type: 'deep_js' })).toEqual({ engine: 'content', message: { action: 'deepJsScan' } });
    expect(mapStepToAction({ type: 'probe_endpoint', target: 'https://x/a' }))
      .toEqual({ engine: 'background', message: { action: 'probeEndpoint', endpoint: 'https://x/a' } });
    expect(mapStepToAction({ type: 'differential_probe', target: 'https://x/?id=1', param: 'id' }))
      .toEqual({ engine: 'background', message: { action: 'differentialProbe', url: 'https://x/?id=1', param: 'id' } });
    expect(mapStepToAction({ type: 'run_payload', payloadFamily: 'xss' }))
      .toEqual({ engine: 'content', message: { action: 'executeVulnTest', vulnKey: 'xss' } });
    expect(mapStepToAction({ type: 'agent_scan', tool: 'httpx', target: 'x.com', profile: 'quick' }))
      .toEqual({ engine: 'background', message: { action: 'agentScan', tool: 'httpx', target: 'x.com', profile: 'quick' } });
  });

  it('returns null for manual (nothing executes)', () => {
    expect(mapStepToAction({ type: 'manual', note: 'try IDOR by hand' })).toBeNull();
  });
});

describe('isSafeStep', () => {
  it('is true only for safe-risk steps', () => {
    expect(isSafeStep({ risk: 'safe' })).toBe(true);
    expect(isSafeStep({ risk: 'active' })).toBe(false);
    expect(isSafeStep(null)).toBe(false);
  });
});

describe('canEscalate / remainingBudget — loop bounds', () => {
  it('allows escalation under both caps', () => {
    expect(canEscalate({ depth: 0, budgetUsed: 0 })).toBe(true);
    expect(canEscalate({ depth: MAX_DEPTH - 1, budgetUsed: DEFAULT_ESCALATION_BUDGET - 1 })).toBe(true);
  });
  it('stops at max depth', () => {
    expect(canEscalate({ depth: MAX_DEPTH, budgetUsed: 0 })).toBe(false);
    expect(canEscalate({ depth: MAX_DEPTH + 5, budgetUsed: 0 })).toBe(false);
  });
  it('stops when the session budget is exhausted', () => {
    expect(canEscalate({ depth: 0, budgetUsed: DEFAULT_ESCALATION_BUDGET })).toBe(false);
  });
  it('remainingBudget never goes negative', () => {
    expect(remainingBudget(0)).toBe(DEFAULT_ESCALATION_BUDGET);
    expect(remainingBudget(DEFAULT_ESCALATION_BUDGET + 10)).toBe(0);
  });
});

describe('ACTION_VERBS sanity', () => {
  it('has no verb that both targets and is mislabeled none', () => {
    for (const [verb, def] of Object.entries(ACTION_VERBS)) {
      expect(['url', 'host', 'none']).toContain(def.targetKind);
      expect(['safe', 'active', 'none']).toContain(def.risk);
      expect(typeof verb).toBe('string');
    }
  });
});
