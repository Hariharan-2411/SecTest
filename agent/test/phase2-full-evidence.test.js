'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { runCommand } = require('../lib/tools');
const { runWithFullEvidence } = require('../lib/fullEvidence');

test('runCommand applies an env overlay to the spawned tool', async () => {
  const r = await runCommand({ bin: 'sh', args: ['-c', 'printf %s "$IRIS_X"'] }, { env: { IRIS_X: 'hi' }, timeoutMs: 5000 });
  assert.equal(r.stdout, 'hi');
});

test('full evidence falls back to Light when mitmdump is unavailable (no throw)', async () => {
  const fakeRun = async () => ({ ok: true, stdout: 'done', code: 0, timedOut: false });
  const out = await runWithFullEvidence({ def: {}, cmd: { bin: 'x', args: [] }, runCommand: fakeRun, binExists: () => false });
  assert.equal(out.evidence.mode, 'light');
  assert.equal(out.result.ok, true);
});

test('full evidence falls back to Light on proxy error (no throw)', async () => {
  const fakeRun = async () => ({ ok: true, stdout: 'done', code: 0, timedOut: false });
  const out = await runWithFullEvidence({
    def: {}, cmd: { bin: 'x', args: [] }, runCommand: fakeRun,
    binExists: () => true,
    spawnImpl: () => { throw new Error('no mitmdump binary'); },
    settleMs: 1,
  });
  assert.equal(out.evidence.mode, 'light');
  assert.equal(out.result.ok, true);
});
