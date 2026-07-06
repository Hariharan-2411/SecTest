// Agent pure-logic tests. Run with:  node --test
'use strict';

const { test } = require('node:test');
const assert = require('node:assert');

const {
  hostFromTarget,
  parseScopeText,
  matchesPattern,
  evaluateTarget,
  isTargetInScope,
} = require('../lib/scope');
const { buildCommand, listTools, TOOLS } = require('../lib/tools');
const { parseOutput } = require('../lib/parse');

test('hostFromTarget strips scheme/port/path', () => {
  assert.equal(hostFromTarget('https://App.Example.com:8443/x?y=1'), 'app.example.com');
  assert.equal(hostFromTarget('example.com'), 'example.com');
});

test('scope wildcard matches apex + subdomains, not lookalikes', () => {
  assert.equal(matchesPattern('a.example.com', '*.example.com'), true);
  assert.equal(matchesPattern('example.com', '*.example.com'), true);
  assert.equal(matchesPattern('example.com.evil.com', '*.example.com'), false);
});

test('evaluateTarget: out-of-scope wins, bare host exact', () => {
  const scope = { inScope: parseScopeText('*.example.com'), outOfScope: parseScopeText('admin.example.com') };
  assert.equal(isTargetInScope('https://app.example.com', scope), true);
  assert.equal(evaluateTarget('admin.example.com', scope).reason, 'out_of_scope');
  assert.equal(isTargetInScope('other.com', scope), false);
  assert.equal(evaluateTarget('x', { inScope: [], outOfScope: [] }).reason, 'no_scope');
});

test('buildCommand produces array args (no shell injection) and known risk', () => {
  const cmd = buildCommand('subfinder', 'https://example.com/path', 'quick');
  assert.equal(cmd.bin, 'subfinder');
  assert.deepEqual(cmd.args, ['-silent', '-d', 'example.com']); // host extracted, no path
  assert.equal(cmd.risk, 'safe');
  assert.ok(Array.isArray(cmd.args));
});

test('buildCommand marks port/vuln tools active and honors profile', () => {
  assert.equal(buildCommand('naabu', 'example.com', 'top1000').risk, 'active');
  assert.ok(buildCommand('naabu', 'example.com', 'top1000').args.includes('1000'));
  assert.equal(buildCommand('nuclei', 'https://example.com').risk, 'active');
});

test('buildCommand rejects unknown tools and bad targets', () => {
  assert.throws(() => buildCommand('rm', 'example.com'), /unknown_tool/);
  assert.throws(() => buildCommand('subfinder', '  '), /bad_target/);
});

test('a malicious target cannot inject flags/commands into args', () => {
  // Even a nasty string is reduced to a host token; it lands as one array elem.
  const cmd = buildCommand('subfinder', 'example.com/;rm -rf /', 'quick');
  assert.equal(cmd.args[cmd.args.length - 1], 'example.com'); // path (and payload) stripped
});

test('listTools exposes risk levels; no destructive tools registered', () => {
  const risks = listTools().map((t) => t.risk);
  assert.ok(risks.every((r) => r === 'safe' || r === 'active'));
  assert.ok(!Object.values(TOOLS).some((t) => t.risk === 'destructive'));
});

test('parseOutput normalizes each tool shape', () => {
  assert.deepEqual(parseOutput('subfinder', 'a.example.com\nb.example.com').items, [
    'a.example.com',
    'b.example.com',
  ]);
  const http = parseOutput('httpx', JSON.stringify({ url: 'https://x', status_code: 200, title: 'Home' }));
  assert.equal(http.items[0].status, 200);
  const ports = parseOutput('naabu', 'x.com:80\nx.com:443');
  assert.equal(ports.items.length, 2);
  assert.equal(ports.items[0].port, '80');
  const nuclei = parseOutput('nuclei', JSON.stringify({ 'template-id': 'cve', info: { severity: 'high' }, 'matched-at': 'x' }));
  assert.equal(nuclei.items[0].severity, 'high');
});

test('content-discovery tools: safe vs active risk and bounded args', () => {
  // gau / waybackurls query archives, not the target → safe.
  assert.equal(buildCommand('gau', 'https://example.com/x').risk, 'safe');
  assert.deepEqual(buildCommand('waybackurls', 'example.com').args, ['example.com']);
  // katana / ffuf / feroxbuster hit the live host → active, host-only variable.
  const katana = buildCommand('katana', 'https://example.com/p', 'deep');
  assert.equal(katana.risk, 'active');
  assert.ok(katana.args.includes('https://example.com'));
  assert.ok(katana.args.includes('3')); // deep profile → depth 3
  const ffuf = buildCommand('ffuf', 'example.com');
  assert.equal(ffuf.risk, 'active');
  assert.ok(ffuf.args.includes('https://example.com/FUZZ'));
  assert.ok(ffuf.args.some((a) => /FUZZ/.test(a)));
});

test('a malicious content-discovery target cannot inject flags', () => {
  const cmd = buildCommand('katana', 'example.com/;curl evil', 'quick');
  // Host is reduced to a single token embedded in a fixed URL arg.
  assert.ok(cmd.args.includes('https://example.com'));
  assert.ok(!cmd.args.some((a) => /curl|;/.test(a)));
});

test('parseOutput folds content-discovery output into deduped urls', () => {
  const gau = parseOutput('gau', 'https://x.com/a\nhttps://x.com/a\nhttps://x.com/b');
  assert.equal(gau.kind, 'urls');
  assert.deepEqual(gau.items, ['https://x.com/a', 'https://x.com/b']);
  const katana = parseOutput('katana', JSON.stringify({ request: { endpoint: 'https://x.com/api' } }));
  assert.equal(katana.kind, 'urls');
  assert.equal(katana.items[0], 'https://x.com/api');
});
