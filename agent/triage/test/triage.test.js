// Triage-agent pure-logic tests.  Run with:  node --test
'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const { SYSTEM_PROMPT, TOOL_DEFS, planScanRequest, makeExecutor, VALID_TOOLS } = require('../tools');

test('TOOL_DEFS expose the three read-through tools with valid schemas', () => {
  const names = TOOL_DEFS.map((t) => t.name).sort();
  assert.deepEqual(names, ['get_scope', 'list_tools', 'recon_scan']);
  for (const t of TOOL_DEFS) {
    assert.equal(t.input_schema.type, 'object');
    assert.equal(t.input_schema.additionalProperties, false);
    assert.ok(typeof t.description === 'string' && t.description.length > 10);
  }
  const scan = TOOL_DEFS.find((t) => t.name === 'recon_scan');
  assert.deepEqual(scan.input_schema.properties.tool.enum, VALID_TOOLS);
});

test('SYSTEM_PROMPT encodes the hard guardrails', () => {
  const p = SYSTEM_PROMPT.toLowerCase();
  assert.ok(p.includes('in-scope'));
  assert.ok(p.includes('do not exploit') || p.includes('not exploit'));
  assert.ok(p.includes('submit')); // must mention the human-owns-submit rule
  assert.ok(p.includes('idor')); // flags candidates, doesn't confirm
});

test('planScanRequest normalizes and defaults the profile', () => {
  assert.deepEqual(planScanRequest({ tool: 'httpx', target: ' example.com ' }), {
    tool: 'httpx',
    target: 'example.com',
    profile: 'quick',
  });
  assert.equal(planScanRequest({ tool: 'nmap', target: 'x.com', profile: 'services' }).profile, 'services');
  assert.equal(planScanRequest({ tool: 'naabu', target: 'x.com', profile: 'bogus' }).profile, 'quick');
});

test('planScanRequest rejects unknown tools and empty targets', () => {
  assert.throws(() => planScanRequest({ tool: 'rm', target: 'x.com' }), /unknown_tool/);
  assert.throws(() => planScanRequest({ tool: 'httpx', target: '  ' }), /missing_target/);
});

test('executor returns a structured error for an unknown tool call (no network)', async () => {
  const exec = makeExecutor({ url: 'http://127.0.0.1:1', token: 't' });
  const out = await exec('definitely_not_a_tool', {});
  assert.match(out.error, /unknown_tool_call/);
});

test('executor recon_scan validates before any network call', async () => {
  const exec = makeExecutor({ url: 'http://127.0.0.1:1', token: 't' });
  const out = await exec('recon_scan', { tool: 'rm', target: 'x.com' }); // invalid tool
  assert.match(out.error, /unknown_tool/); // caught by planScanRequest, never dials out
});
