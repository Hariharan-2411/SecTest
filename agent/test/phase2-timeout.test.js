'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { TOOLS, runCommand } = require('../lib/tools');

test('confirmation tools carry a longer (but bounded) timeout', () => {
  for (const t of ['sqlmap', 'sstimap', 'commix']) {
    assert.ok(typeof TOOLS[t].timeoutMs === 'number', `${t} needs timeoutMs`);
    assert.ok(TOOLS[t].timeoutMs >= 300000, `${t} timeout should be >= 5min`);
  }
  // non-confirmation tool has no override (uses the 120s default)
  assert.equal(TOOLS.httpx.timeoutMs, undefined);
});

test('runCommand honors an injected timeout and hard-kills (still bounded)', async () => {
  const r = await runCommand({ bin: 'sleep', args: ['5'] }, { timeoutMs: 250 });
  assert.equal(r.timedOut, true);
});
