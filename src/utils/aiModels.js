// Friendly labels for the Groq model dropdown. Editable: add/adjust hints here.
// The live list comes from the proxy's /models route; unknown ids fall back to
// their raw name so the dropdown stays current even as Groq adds/retires models.

export const DEFAULT_MODEL = 'llama-3.3-70b-versatile';

export const MODEL_HINTS = {
  'llama-3.3-70b-versatile': { label: '⭐ Recommended — best overall quality', tier: 'recommended' },
  'llama-3.1-8b-instant': { label: '⚡ Fastest — quick, simple payloads', tier: 'fast' },
  'deepseek-r1-distill-llama-70b': { label: '🧠 Reasoning — complex / multi-step chains', tier: 'reasoning' },
  'gemma2-9b-it': { label: '🪶 Lightweight alternative', tier: 'light' },
  'llama3-70b-8192': { label: 'Llama 3 70B', tier: 'other' },
  'llama3-8b-8192': { label: 'Llama 3 8B', tier: 'other' },
};

// Merge live model ids with the hint map. Known ids get a friendly label;
// unknown/new ids pass through with their raw name (still selectable). Falls
// back to the hint-map keys if the live list is empty.
export function decorate(liveIds = []) {
  const ids =
    Array.isArray(liveIds) && liveIds.length ? liveIds : Object.keys(MODEL_HINTS);
  return ids.map((id) => ({
    id,
    label: (MODEL_HINTS[id] && MODEL_HINTS[id].label) || id,
    tier: (MODEL_HINTS[id] && MODEL_HINTS[id].tier) || 'other',
  }));
}
