#!/usr/bin/env node
/*
 Simple local proxy for Ollama API to work around browser/extension Origin restrictions.

 Usage:
   node scripts/ollama-proxy.js

 Options via env:
   PROXY_PORT=5000
   OLLAMA_BASE=http://127.0.0.1:11434

 Then set the extension's Ollama Base URL to http://127.0.0.1:5000
*/

const http = require('http');
const https = require('https');
const { URL } = require('url');

let PORT = parseInt(process.env.PROXY_PORT || process.argv[2] || '5000', 10);
const TARGET_BASE = process.env.OLLAMA_BASE || 'http://127.0.0.1:11434';
const TARGET = new URL(TARGET_BASE);
const AGENTS = {
  'http:': new http.Agent({ keepAlive: false }),
  'https:': new https.Agent({ keepAlive: false })
};

function setCors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', '*');
}

function createServer() {
  const server = http.createServer((req, res) => {
  // CORS preflight
  if (req.method === 'OPTIONS') {
    setCors(res);
    res.writeHead(200);
    res.end();
    return;
  }

  // Only forward /api/*; anything else returns basic info
  if (!req.url.startsWith('/api/')) {
    setCors(res);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, message: 'Ollama proxy alive', target: TARGET_BASE }));
    return;
  }

  const targetUrl = new URL(req.url, TARGET_BASE);
  const isHttps = TARGET.protocol === 'https:';
  const transport = isHttps ? https : http;

  // Clone and sanitize headers
  const headers = { ...req.headers };
  delete headers['origin'];
  delete headers['referer'];
  headers['host'] = TARGET.host;
  headers['connection'] = 'close';

  const options = {
    protocol: TARGET.protocol,
    hostname: TARGET.hostname,
    port: TARGET.port || (isHttps ? 443 : 80),
    method: req.method,
    path: targetUrl.pathname + targetUrl.search,
    headers,
    agent: AGENTS[TARGET.protocol]
  };

  const proxyReq = transport.request(options, (proxyRes) => {
    setCors(res);
    // Pass through status and headers (with permissive CORS)
    const respHeaders = { ...proxyRes.headers };
    delete respHeaders['content-security-policy'];
    delete respHeaders['content-security-policy-report-only'];
    Object.entries(respHeaders).forEach(([k, v]) => {
      try { res.setHeader(k, v); } catch (_) {}
    });
    res.writeHead(proxyRes.statusCode || 502);
    proxyRes.pipe(res);
  });

  proxyReq.on('error', (err) => {
    setCors(res);
    res.writeHead(502, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: false, error: 'Proxy error', message: err.message }));
  });

  // Pipe request body
  req.pipe(proxyReq);
  });

  server.on('error', (err) => {
    if (err && err.code === 'EADDRINUSE') {
      const next = PORT + 1;
      console.warn(`[ollama-proxy] Port ${PORT} in use, retrying on ${next}...`);
      PORT = next;
      setTimeout(() => {
        try { server.close(); } catch (_) {}
        createServer();
      }, 100);
    } else {
      console.error('[ollama-proxy] Server error:', err);
    }
  });

  server.listen(PORT, () => {
    console.log(`[ollama-proxy] listening on http://127.0.0.1:${PORT} -> ${TARGET_BASE}`);
  });
}

createServer();
