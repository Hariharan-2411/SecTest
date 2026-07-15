import { describe, it, expect } from '@jest/globals';
import {
  RECON_TOOLS,
  RECON_PROFILES,
  RISK_POLICY,
  MAX_RECON_STEPS,
  normalizeToolCall,
  normalizeReconPlan,
  rankTriage,
} from '../src/utils/reconAgent';

const scope = {
  inScope: ['*.example.com', 'example.com'],
  outOfScope: ['admin.example.com'],
};
const ctx = { scope };

describe('RECON_TOOLS registry', () => {
  it('tags the safe and active recon tools to match the companion agent', () => {
    for (const t of ['subfinder', 'dnsx', 'httpx', 'gau', 'waybackurls']) {
      expect(RECON_TOOLS[t].risk).toBe('safe');
    }
    for (const t of [
      'naabu',
      'nmap',
      'nuclei',
      'katana',
      'ffuf',
      'feroxbuster',
    ]) {
      expect(RECON_TOOLS[t].risk).toBe('active');
    }
  });

  it('registers no destructive tools', () => {
    for (const name of Object.keys(RECON_TOOLS)) {
      expect(['safe', 'active']).toContain(RECON_TOOLS[name].risk);
    }
  });
});

describe('normalizeToolCall — scope + risk + budget gate', () => {
  it('auto-allows an in-scope safe tool', () => {
    const d = normalizeToolCall(
      { tool: 'subfinder', target: 'app.example.com' },
      ctx
    );
    expect(d.decision).toBe('allow');
    expect(d.call.risk).toBe('safe');
    expect(d.call.profile).toBe('quick'); // default
  });

  it('gates an in-scope active tool on human approval', () => {
    const d = normalizeToolCall(
      { tool: 'nuclei', target: 'app.example.com' },
      ctx
    );
    expect(d.decision).toBe('needs_approval');
    expect(d.call.risk).toBe('active');
  });

  it('recomputes risk from the registry — the model cannot downgrade an active tool', () => {
    const d = normalizeToolCall(
      { tool: 'nuclei', target: 'app.example.com', risk: 'safe' },
      ctx
    );
    expect(d.decision).toBe('needs_approval');
    expect(d.call.risk).toBe('active');
  });

  it('denies an unknown tool', () => {
    const d = normalizeToolCall(
      { tool: 'metasploit', target: 'app.example.com' },
      ctx
    );
    expect(d.decision).toBe('deny');
    expect(d.reason).toMatch(/unknown_tool/);
    expect(d.call).toBeNull();
  });

  it('denies an out-of-scope target', () => {
    const d = normalizeToolCall({ tool: 'httpx', target: 'evil.com' }, ctx);
    expect(d.decision).toBe('deny');
    expect(d.reason).toMatch(/out_of_scope/);
  });

  it('denies a missing/blank target', () => {
    expect(normalizeToolCall({ tool: 'httpx' }, ctx).reason).toBe('bad_target');
    expect(
      normalizeToolCall({ tool: 'httpx', target: '   ' }, ctx).reason
    ).toBe('bad_target');
  });

  it('denies once the per-run budget is spent', () => {
    const d = normalizeToolCall(
      { tool: 'subfinder', target: 'app.example.com' },
      { scope, budgetUsed: 20, budget: 20 }
    );
    expect(d.decision).toBe('deny');
    expect(d.reason).toBe('over_budget');
  });

  it('normalizes an unknown profile to the default and keeps a valid one', () => {
    expect(
      normalizeToolCall(
        { tool: 'nmap', target: 'app.example.com', profile: 'bogus' },
        ctx
      ).call.profile
    ).toBe('quick');
    expect(
      normalizeToolCall(
        { tool: 'nmap', target: 'app.example.com', profile: 'services' },
        ctx
      ).call.profile
    ).toBe('services');
  });

  it('respects a caller policy override for active tools', () => {
    const allow = normalizeToolCall(
      { tool: 'nuclei', target: 'app.example.com' },
      { scope, policy: { ...RISK_POLICY, active: 'allow' } }
    );
    expect(allow.decision).toBe('allow');
    const deny = normalizeToolCall(
      { tool: 'nuclei', target: 'app.example.com' },
      { scope, policy: { ...RISK_POLICY, active: 'deny' } }
    );
    expect(deny.decision).toBe('deny');
  });
});

describe('normalizeReconPlan — validate a whole plan', () => {
  it('classifies each step and mixes allow/approval/deny', () => {
    const raw = {
      steps: [
        { tool: 'subfinder', target: 'app.example.com' }, // allow
        { tool: 'nuclei', target: 'app.example.com' }, // needs_approval
        { tool: 'nmap', target: 'evil.com' }, // deny (scope)
      ],
    };
    const { steps, rejected } = normalizeReconPlan(raw, ctx);
    expect(steps.map((s) => s.decision)).toEqual([
      'allow',
      'needs_approval',
      'deny',
    ]);
    expect(rejected).toHaveLength(0);
  });

  it('caps the number of steps at MAX_RECON_STEPS', () => {
    const one = { tool: 'subfinder', target: 'app.example.com' };
    const raw = {
      steps: Array.from({ length: MAX_RECON_STEPS + 3 }, () => one),
    };
    const { steps, rejected } = normalizeReconPlan(raw, ctx);
    expect(steps).toHaveLength(MAX_RECON_STEPS);
    expect(rejected.some((r) => r.reason === 'over_cap')).toBe(true);
  });

  it('tolerates junk input', () => {
    expect(normalizeReconPlan(null, ctx)).toEqual({ steps: [], rejected: [] });
    expect(normalizeReconPlan({ steps: 'nope' }, ctx).steps).toEqual([]);
  });
});

describe('rankTriage — deterministic ranking', () => {
  it('orders findings by severity then confidence and assigns a rank', () => {
    const out = rankTriage([
      { title: 'a', severity: 'low', confidence: 80 },
      { title: 'b', severity: 'critical', confidence: 10 },
      { title: 'c', severity: 'critical', confidence: 90 },
    ]);
    expect(out.map((f) => f.title)).toEqual(['c', 'b', 'a']); // critical(90), critical(10), low
    expect(out.map((f) => f.rank)).toEqual([1, 2, 3]);
  });

  it('tolerates a non-array', () => {
    expect(rankTriage(null)).toEqual([]);
  });
});

describe('exports', () => {
  it('exposes the profile set and default risk policy', () => {
    expect(RECON_PROFILES).toEqual(
      expect.arrayContaining(['quick', 'top1000', 'services', 'deep'])
    );
    expect(RISK_POLICY).toEqual({
      safe: 'allow',
      active: 'needs_approval',
      destructive: 'deny',
    });
  });
});
