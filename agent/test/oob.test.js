// OOB collector pure-logic tests.  Run with:  node --test
'use strict';

const { test } = require('node:test');
const assert = require('node:assert');

const {
  extractCid,
  mintCid,
  createRegistry,
  registerCid,
  recordInteraction,
  pollInteractions,
} = require('../lib/oob');

test('extractCid takes the first path segment when it looks like a cid', () => {
  assert.equal(extractCid('/ab12cd34/foo'), 'ab12cd34');
  assert.equal(extractCid('/AB12CD34'), 'ab12cd34'); // lowercased
  assert.equal(extractCid('/'), ''); // no segment
  assert.equal(extractCid('/x'), ''); // too short to be a cid
  assert.equal(extractCid('/not a cid/'), '');
});

test('mintCid is unguessable and unique', () => {
  const a = mintCid();
  const b = mintCid();
  assert.match(a, /^[a-f0-9]{16}$/);
  assert.notEqual(a, b);
});

test('registered cid polls to an empty array (tracked, not unknown)', () => {
  const reg = createRegistry();
  const cid = mintCid();
  registerCid(reg, cid);
  assert.deepEqual(pollInteractions(reg, cid), []);
});

test('recordInteraction stores and polls back per cid', () => {
  const reg = createRegistry();
  const cid = mintCid();
  assert.equal(recordInteraction(reg, cid, { method: 'GET', path: '/' + cid }), true);
  assert.equal(recordInteraction(reg, '', { method: 'GET' }), false); // no cid → ignored
  const hits = pollInteractions(reg, cid);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].method, 'GET');
});

test('per-cid interactions are capped (bounded memory)', () => {
  const reg = createRegistry({ maxPerCid: 3 });
  const cid = mintCid();
  for (let i = 0; i < 10; i++) recordInteraction(reg, cid, { n: i });
  const hits = pollInteractions(reg, cid);
  assert.equal(hits.length, 3);
  assert.equal(hits[hits.length - 1].n, 9); // keeps newest
});

test('registry evicts oldest cid past maxCids', () => {
  const reg = createRegistry({ maxCids: 2 });
  registerCid(reg, 'aaaaaa');
  registerCid(reg, 'bbbbbb');
  registerCid(reg, 'cccccc'); // evicts aaaaaa
  assert.equal(reg.map.has('aaaaaa'), false);
  assert.equal(reg.map.has('cccccc'), true);
});
