import { describe, it, expect } from '@jest/globals';
import { TASK_MODEL_TIERS, modelForTask } from '../src/utils/modelRouter';
import { DEFAULT_MODEL } from '../src/utils/aiModels';

// Mirrors the decorate() output shape the Popup holds.
const models = [
  { id: 'llama-3.3-70b-versatile', tier: 'recommended' },
  { id: 'llama-3.1-8b-instant', tier: 'fast' },
  { id: 'deepseek-r1-distill-llama-70b', tier: 'reasoning' },
  { id: 'gemma2-9b-it', tier: 'light' },
];
const selected = 'llama-3.3-70b-versatile';

describe('TASK_MODEL_TIERS', () => {
  it('maps the high-volume tasks to fast and the hard-reasoning tasks to reasoning', () => {
    expect(TASK_MODEL_TIERS.payload).toBe('fast');
    expect(TASK_MODEL_TIERS.chains).toBe('reasoning');
    expect(TASK_MODEL_TIERS.escalate).toBe('reasoning');
    expect(TASK_MODEL_TIERS.report).toBe('recommended');
    expect(TASK_MODEL_TIERS.chat).toBe('selected');
  });
});

describe('modelForTask', () => {
  it('routes a fast-tier task to the available fast model', () => {
    expect(modelForTask('payload', { selected, models })).toBe('llama-3.1-8b-instant');
  });

  it('routes reasoning-tier tasks to the available reasoning model', () => {
    expect(modelForTask('chains', { selected, models })).toBe('deepseek-r1-distill-llama-70b');
    expect(modelForTask('escalate', { selected, models })).toBe('deepseek-r1-distill-llama-70b');
    expect(modelForTask('triage', { selected, models })).toBe('deepseek-r1-distill-llama-70b');
  });

  it('routes the report task to the recommended model', () => {
    expect(modelForTask('report', { selected, models })).toBe('llama-3.3-70b-versatile');
  });

  it('never overrides the interactive chat task — always the user pick', () => {
    expect(modelForTask('chat', { selected, models })).toBe(selected);
  });

  it('returns the selected model for an unknown task', () => {
    expect(modelForTask('mystery', { selected, models })).toBe(selected);
  });

  it('returns the selected model for every task when autoRoute is off', () => {
    expect(modelForTask('payload', { selected, models, autoRoute: false })).toBe(selected);
    expect(modelForTask('chains', { selected, models, autoRoute: false })).toBe(selected);
  });

  it('falls back to the selected model when the tier is not available', () => {
    const only = [{ id: 'llama-3.3-70b-versatile', tier: 'recommended' }];
    // no reasoning model in the list -> fall back to selected
    expect(modelForTask('chains', { selected, models: only })).toBe('llama-3.3-70b-versatile');
  });

  it('falls back to DEFAULT_MODEL when there is no selection and no matching model', () => {
    expect(modelForTask('payload', {})).toBe(DEFAULT_MODEL);
    expect(modelForTask('payload', { models: [] })).toBe(DEFAULT_MODEL);
  });

  it('never throws on a non-array models input', () => {
    expect(() => modelForTask('payload', { selected, models: null })).not.toThrow();
    expect(modelForTask('payload', { selected, models: null })).toBe(selected);
  });
});
