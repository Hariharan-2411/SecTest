'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { TOOLS, listTools, buildCommand, targetEndpoint } = require('../lib/tools');
const { parseOutput } = require('../lib/parse');

test('dalfox and sqlmap are registered as destructive', () => {
  assert.equal(TOOLS.dalfox.risk, 'destructive');
  assert.equal(TOOLS.sqlmap.risk, 'destructive');
  const risks = Object.fromEntries(listTools().map((t) => [t.name, t.risk]));
  assert.equal(risks.dalfox, 'destructive');
  assert.equal(risks.sqlmap, 'destructive');
});

test('sqlmap args are DETECTION-ONLY — never exfiltration/exec', () => {
  const { args } = buildCommand('sqlmap', 'https://app.example.com/p?id=1');
  const joined = args.join(' ');
  for (const banned of ['--dump', '--dump-all', '--os-shell', '--os-pwn', '--file-read', '--file-write', '--sql-shell', '--tamper']) {
    assert.ok(!joined.includes(banned), `sqlmap must not use ${banned}`);
  }
  assert.ok(joined.includes('--batch'));
  const tech = (joined.match(/--technique=(\w+)/) || [])[1] || '';
  assert.ok(tech.length > 0, 'a detection technique is set');
  assert.ok(!tech.includes('S'), 'no stacked-query technique (no multi-statement writes)');
});

test('buildCommand passes args as an array (no shell string), host-scoped', () => {
  const { bin, args, host } = buildCommand('dalfox', 'https://app.example.com/x');
  assert.equal(bin, 'dalfox');
  assert.ok(Array.isArray(args));
  assert.equal(host, 'app.example.com');
  assert.ok(args.includes('https://app.example.com/x')); // endpoint preserves scheme + path
});

test('targetEndpoint honors scheme + port, defaults https, preserves path/query', () => {
  assert.equal(targetEndpoint('http://localhost:3000'), 'http://localhost:3000');
  assert.equal(targetEndpoint('app.example.com'), 'https://app.example.com');
  assert.equal(targetEndpoint('example.com:8080'), 'https://example.com:8080');
  assert.equal(targetEndpoint('http://t.vulnweb.com/listproducts.php?cat=1'),
               'http://t.vulnweb.com/listproducts.php?cat=1');
});

test('URL tools receive the normalized endpoint (http + non-standard port)', () => {
  const sql = buildCommand('sqlmap', 'http://localhost:3000').args.join(' ');
  assert.ok(sql.includes('-u http://localhost:3000'));
  const hx = buildCommand('httpx', 'http://localhost:3000').args.join(' ');
  assert.ok(hx.includes('-u http://localhost:3000'));
  const fx = buildCommand('ffuf', 'http://localhost:3000').args.join(' ');
  assert.ok(fx.includes('http://localhost:3000/FUZZ'));
});

test('buildCommand applies a per-engagement req/s rate to rate-capable tools', () => {
  // native req/s flags: override (nuclei/ffuf) or append (httpx/katana)
  assert.match(buildCommand('nuclei', 'https://h/', 'quick', { rate: 5 }).args.join(' '), /-rate-limit 5\b/);
  assert.match(buildCommand('httpx', 'https://h/', 'quick', { rate: 3 }).args.join(' '), /-rl 3\b/);
  assert.match(buildCommand('ffuf', 'https://h/', 'quick', { rate: 7 }).args.join(' '), /-rate 7\b/);
  // injection tools get an inter-request delay instead
  assert.match(buildCommand('sqlmap', 'https://h/?id=1', 'quick', { rate: 5 }).args.join(' '), /--delay 0\.20/);
  // no rate → bounded defaults untouched
  assert.match(buildCommand('nuclei', 'https://h/', 'quick').args.join(' '), /-rate-limit 50\b/);
});

test('parseOutput(dalfox) → findings from JSON PoCs', () => {
  const out = JSON.stringify([{ type: 'reflected', data: 'https://app.example.com/?q=<svg/onload>' }]);
  const r = parseOutput('dalfox', out);
  assert.equal(r.kind, 'findings');
  assert.equal(r.count, 1);
  assert.match(r.items[0].name, /XSS/);
});

test('parseOutput(sqlmap) → finding only when injectable', () => {
  const vuln = parseOutput('sqlmap', 'sqlmap identified the following injection point\nParameter: id (GET)\n  Type: boolean-based blind');
  assert.equal(vuln.count, 1);
  assert.match(vuln.items[0].name, /SQL injection/);
  const clean = parseOutput('sqlmap', 'all tested parameters do not appear to be injectable');
  assert.equal(clean.count, 0);
});
