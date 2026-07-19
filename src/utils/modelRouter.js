// Multi-model routing — pick the Groq model tier that fits each task. Pure,
// unit-testable (no chrome.*/network).
//
// The codebase tags every model with a tier (aiModels.MODEL_HINTS). Rather than
// send every AI call to the one model the user picked, route by TASK CLASS: a
// fast model for high-volume mechanical calls, a reasoning model for the hard
// steps, the recommended model for report prose. Routing only ever picks from the
// user's LIVE model list, so it never routes to a model their account lacks, and
// it always degrades to the user's selection — never a cage.

import { DEFAULT_MODEL } from './aiModels';

// Task class -> desired model tier. Tiers match aiModels.MODEL_HINTS.
// 'selected' means "honor the user's exact pick" (the interactive AI-tab chat).
export const TASK_MODEL_TIERS = {
  payload: 'fast',
  reconPlan: 'fast',
  confidenceProse: 'fast',
  chains: 'reasoning',
  escalate: 'reasoning',
  triage: 'reasoning',
  report: 'recommended',
  chat: 'selected',
};

/**
 * Resolve the model id to use for a task. Pure; never throws.
 * @param {string} task  a TASK_MODEL_TIERS key
 * @param {{selected?:string, models?:{id:string,tier:string}[], autoRoute?:boolean}} opts
 *   models = the decorated live list (id + tier); autoRoute defaults true.
 * @returns {string} model id — the tier's available model, else selected, else DEFAULT_MODEL
 */
export function modelForTask(task, { selected, models = [], autoRoute = true } = {}) {
  const fallback = selected || DEFAULT_MODEL;
  if (!autoRoute) return fallback;
  const tier = TASK_MODEL_TIERS[task];
  if (!tier || tier === 'selected') return fallback;
  const match = (Array.isArray(models) ? models : []).find((m) => m && m.tier === tier);
  return (match && match.id) || fallback;
}
