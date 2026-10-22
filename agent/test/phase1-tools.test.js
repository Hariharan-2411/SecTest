'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { existsSync, statSync } = require('fs');
const { TOOLS, buildCommand } = require('../lib/tools');
const { parseOutput } = require('../lib/parse');
const { fetchToTempDir } = require('../lib/fetchContent');

const SAFE = ['assetfinder', 'wafw00f', 'cvemap', 'trufflehog', 'gitleaks'];
const ACTIVE = ['amass', 'puredns', 'arjun', 'subzy', 's3scanner', 'crlfuzz', 'jwt_tool', 'wpscan', 'gowitness'];
const DESTR = ['sstimap', 'commix'];

test('risk tiers match the design for all new tools', () => {
  for (const t of SAFE) assert.equal(TOOLS[t].risk, 'safe', t);
  for (const t of ACTIVE) assert.equal(TOOLS[t].risk, 'active', t);
  for (const t of DESTR) assert.equal(TOOLS[t].risk, 'destructive', t);
});

test('destructive injection tools are DETECTION-ONLY (no exfil/shell/file flags)', () => {
  for (const t of DESTR) {
    const { args } = buildCommand(t, 'https://app.example.com/p?id=1');
    const j = args.join(' ');
    for (const banned of ['--os-shell', '--os-cmd', '--os-pwn', '--file-write', '--file-read', '--dump', '--sql-shell', '--eval']) {
      assert.ok(!j.includes(banned), `${t} must not use ${banned}`);
    }
    assert.ok(j.includes('--batch'), `${t} should be non-interactive`);
  }
});

test('URL tools keep a malicious target inert (array args, no shell tokens)', () => {
  const cmd = buildCommand('crlfuzz', 'https://x.example.com/;curl evil');
  assert.ok(Array.isArray(cmd.args));
  assert.ok(cmd.args.some((a) => a.startsWith('https://x.example.com'))); // one element
  assert.ok(!cmd.args.some((a) => !/^https?:/.test(a) && /;|curl evil/.test(a)));
});

test('content-mode tools refuse the normal buildCommand path', () => {
  assert.throws(() => buildCommand('trufflehog', 'https://x.example.com'), /content_tool/);
  assert.equal(TOOLS.trufflehog.mode, 'content');
  assert.equal(typeof TOOLS.gitleaks.buildContent, 'function');
});

test('wpscan omits --api-token when no key is set (ship-and-degrade)', () => {
  delete process.env.WPSCAN_API_TOKEN;
  const { args } = buildCommand('wpscan', 'https://wp.example.com');
  assert.ok(!args.includes('--api-token'));
});

test('parsers produce the expected kinds/types', () => {
  assert.equal(parseOutput('assetfinder', 'a.example.com\nb.example.com').kind, 'subdomains');
  assert.equal(parseOutput('amass', 'a.example.com').count, 1);
  assert.equal(parseOutput('subzy', '[ VULNERABLE ] sub.example.com -> svc').items[0].type, 'takeover');
  assert.equal(parseOutput('s3scanner', 'bucket x | open to AllUsers').items[0].type, 's3-exposure');
  assert.equal(parseOutput('crlfuzz', 'https://x.example.com/%0d%0aSet-Cookie:x').items[0].type, 'crlf');
  assert.equal(parseOutput('sstimap', 'SSTImap: the target is vulnerable. Engine: Jinja2').items[0].type, 'ssti');
  assert.equal(parseOutput('commix', 'the parameter appears to be injectable').items[0].type, 'cmd-injection');
  assert.equal(parseOutput('wafw00f', '[{"url":"x","detected":true,"firewall":"Cloudflare"}]').kind, 'info');
});

test('secret parsers MASK the value', () => {
  const g = parseOutput('gitleaks', '[{"RuleID":"aws","Secret":"AKIAABCDEFGH1234567890"}]');
  assert.equal(g.items[0].type, 'secrets');
  assert.ok(!g.items[0].matched.includes('AKIAABCDEFGH1234567890'));
  assert.ok(/\*\*\*/.test(g.items[0].matched));
});

test('fetchToTempDir bounds body size and cleans up', async () => {
  const big = 'A'.repeat(5 * 1024 * 1024);
  const fetchImpl = async () => ({ text: async () => big });
  const { dir, files, cleanup } = await fetchToTempDir('https://x.example.com', { maxBytes: 1024, fetchImpl });
  assert.equal(files.length, 1);
  assert.ok(statSync(files[0]).size <= 1024);
  cleanup();
  assert.ok(!existsSync(dir));
});
