// Phase 4 orchestration pure-logic tests.  Run with:  node --test
'use strict';

const { test } = require('node:test');
const assert = require('node:assert');

const { diffSnapshots, summarizeDiff, normalizeSnapshot } = require('../lib/recondiff');
const { createWatch, isDue, recordRun, summarizeWatch } = require('../lib/watches');
const { formatWatchTitle, formatWatchBody, buildWebhookPayload } = require('../lib/notify');

// ---- recondiff -------------------------------------------------------------
test('diffSnapshots flags first run and counts all added', () => {
  const d = diffSnapshots(null, { subdomains: ['a.x.com', 'b.x.com'] });
  assert.equal(d.isFirst, true);
  assert.equal(d.counts.subdomains.added, 2);
  assert.equal(d.addedTotal, 2);
});

test('diffSnapshots detects added/removed across categories', () => {
  const prev = { subdomains: ['a.x.com'], http: [{ url: 'https://a' }] };
  const next = { subdomains: ['a.x.com', 'b.x.com'], http: [{ url: 'https://c' }] };
  const d = diffSnapshots(prev, next);
  assert.deepEqual(d.added.subdomains, ['b.x.com']);
  assert.equal(d.added.http[0].url, 'https://c');
  assert.equal(d.removed.http[0].url, 'https://a');
  assert.equal(d.interesting, true);
});

test('diffSnapshots not interesting when nothing added', () => {
  const prev = { subdomains: ['a', 'b'] };
  const next = { subdomains: ['a'] }; // only a removal
  const d = diffSnapshots(prev, next);
  assert.equal(d.interesting, true === false ? true : d.addedTotal > 0); // addedTotal 0
  assert.equal(d.addedTotal, 0);
  assert.equal(d.interesting, false);
});

test('findings keyed by template+match; nmap ports keyed by host:port', () => {
  const prev = { findings: [{ templateId: 'cve-1', matched: 'x' }], ports: [{ host: 'x', port: '80' }] };
  const next = {
    findings: [{ templateId: 'cve-1', matched: 'x' }, { templateId: 'cve-2', matched: 'y' }],
    ports: [{ host: 'x', port: '80' }, { host: 'x', port: '443' }],
  };
  const d = diffSnapshots(prev, next);
  assert.equal(d.added.findings.length, 1);
  assert.equal(d.added.findings[0].templateId, 'cve-2');
  assert.equal(d.added.ports.length, 1);
  assert.ok(summarizeDiff(d).includes('findings'));
});

test('normalizeSnapshot coerces missing categories to arrays', () => {
  const n = normalizeSnapshot({ subdomains: ['a'] });
  assert.ok(Array.isArray(n.http));
  assert.equal(n.subdomains.length, 1);
});

// ---- watches ---------------------------------------------------------------
test('createWatch normalizes interval floor and default tools', () => {
  const w = createWatch({ target: ' x.com ', intervalMinutes: 5 });
  assert.equal(w.target, 'x.com');
  assert.equal(w.intervalMinutes, 15); // floored
  assert.deepEqual(w.tools, ['subfinder', 'httpx']);
});

test('isDue: never-run is due; recently-run is not', () => {
  const w = createWatch({ target: 'x.com', intervalMinutes: 60 });
  assert.equal(isDue(w, Date.now()), true);
  const ran = { ...w, lastRun: new Date().toISOString() };
  assert.equal(isDue(ran, Date.now()), false);
  const old = { ...w, lastRun: new Date(Date.now() - 61 * 60000).toISOString() };
  assert.equal(isDue(old, Date.now()), true);
});

test('isDue false while running', () => {
  const w = { ...createWatch({ target: 'x.com' }), running: true };
  assert.equal(isDue(w, Date.now()), false);
});

test('recordRun: first run records baseline but is not interesting', () => {
  const w = createWatch({ target: 'x.com' });
  const { watch, interesting } = recordRun(w, { subdomains: ['a.x.com'] }, '2026-01-01T00:00:00Z');
  assert.equal(interesting, false); // baseline
  assert.equal(watch.history.length, 1);
  assert.equal(watch.lastRun, '2026-01-01T00:00:00Z');
  assert.deepEqual(watch.lastSnapshot.subdomains, ['a.x.com']);
});

test('recordRun: second run with new item is interesting', () => {
  let w = createWatch({ target: 'x.com' });
  w = recordRun(w, { subdomains: ['a.x.com'] }, '2026-01-01T00:00:00Z').watch;
  const res = recordRun(w, { subdomains: ['a.x.com', 'b.x.com'] }, '2026-01-02T00:00:00Z');
  assert.equal(res.interesting, true);
  assert.equal(res.delta.added.subdomains[0], 'b.x.com');
  assert.equal(res.watch.history.length, 2);
});

test('summarizeWatch surfaces last summary', () => {
  let w = createWatch({ target: 'x.com' });
  w = recordRun(w, { subdomains: ['a'] }).watch;
  const s = summarizeWatch(w);
  assert.equal(s.target, 'x.com');
  assert.equal(s.runs, 1);
});

// ---- notify ----------------------------------------------------------------
test('notify formats title/body and platform payloads', () => {
  const delta = diffSnapshots({ subdomains: ['a'] }, { subdomains: ['a', 'b.x.com'] });
  assert.ok(formatWatchTitle('x.com', delta.addedTotal).includes('x.com'));
  assert.ok(formatWatchBody('x.com', delta).includes('b.x.com'));
  assert.ok(buildWebhookPayload('discord', 'T', 'B').content.includes('T'));
  assert.equal(buildWebhookPayload('telegram', 'T', 'B').parse_mode, 'Markdown');
  assert.ok(typeof buildWebhookPayload('slack', 'T', 'B').text === 'string');
});
