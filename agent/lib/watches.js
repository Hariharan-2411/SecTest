// Watch model — a scheduled recon job against one in-scope target. Pure logic
// (create / due-check / apply-a-run); the server owns the timers, tool exec,
// and persistence. A "snapshot" is the shape recondiff expects.

'use strict';

const crypto = require('crypto');
const { diffSnapshots, summarizeDiff } = require('./recondiff');

// Tools a watch may schedule (must exist in tools.js). Default to the safe,
// high-signal recon chain; the caller can override.
const DEFAULT_TOOLS = ['subfinder', 'httpx'];

function newId() {
  return 'w_' + crypto.randomBytes(6).toString('hex');
}

/** Create a watch record. */
function createWatch({ target, tools, intervalMinutes = 360 } = {}) {
  const t = String(target || '').trim();
  const chosen = Array.isArray(tools) && tools.length ? tools.slice(0, 8) : DEFAULT_TOOLS.slice();
  return {
    id: newId(),
    target: t,
    tools: chosen,
    intervalMinutes: Math.max(15, Number(intervalMinutes) || 360),
    createdAt: new Date().toISOString(),
    lastRun: null,
    running: false,
    lastSnapshot: null,
    history: [], // [{ ts, summary, counts, addedTotal }]
  };
}

/** Is a watch due to run at time `now` (ms)? */
function isDue(watch, now = Date.now()) {
  if (!watch || watch.running) return false;
  if (!watch.lastRun) return true; // never run → due
  const last = Date.parse(watch.lastRun) || 0;
  return now - last >= watch.intervalMinutes * 60000;
}

/**
 * Apply a completed run's snapshot to a watch: diff vs last, update history and
 * lastSnapshot, and return the delta. Returns a NEW watch (immutably).
 * @returns {{watch:object, delta:object, interesting:boolean}}
 */
function recordRun(watch, snapshot, now = new Date().toISOString()) {
  const delta = diffSnapshots(watch.lastSnapshot, snapshot);
  const summary = summarizeDiff(delta);
  const entry = { ts: now, summary, counts: delta.counts, addedTotal: delta.addedTotal, isFirst: delta.isFirst };
  const history = [entry, ...(watch.history || [])].slice(0, 100);
  const nextWatch = {
    ...watch,
    lastRun: now,
    running: false,
    lastSnapshot: snapshot,
    history,
  };
  // A baseline (first) run is recorded but is not itself "interesting" to alert on.
  const interesting = delta.interesting && !delta.isFirst;
  return { watch: nextWatch, delta, interesting };
}

/** Compact summary for listing. */
function summarizeWatch(watch) {
  const last = (watch.history && watch.history[0]) || null;
  return {
    id: watch.id,
    target: watch.target,
    tools: watch.tools,
    intervalMinutes: watch.intervalMinutes,
    lastRun: watch.lastRun,
    running: !!watch.running,
    runs: (watch.history || []).length,
    lastSummary: last ? last.summary : null,
  };
}

module.exports = { DEFAULT_TOOLS, createWatch, isDue, recordRun, summarizeWatch, newId };
