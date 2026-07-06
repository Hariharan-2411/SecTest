// Out-of-band interaction collector — confirms BLIND vulnerabilities.
//
// Some bugs produce no visible response (blind SSRF, blind RCE, some XXE). The
// classic confirmation is out-of-band: put a unique callback URL in the payload;
// if the target's backend fetches it, you KNOW input reached a network sink.
// This is an HTTP-only, self-hosted catcher: it mints a correlation id (cid),
// you embed `http://<oob-host>/<cid>` in a payload, and any inbound request whose
// first path segment is that cid is recorded and pollable.
//
// SCOPE / SAFETY: opt-in (AGENT_OOB_ENABLE) and gated by AGENT_ALLOW_ACTIVE. It
// only LISTENS — it never sends. By default it binds to 127.0.0.1, so only
// same-host callbacks are caught; catching external callbacks requires the
// operator to deliberately bind wider (documented trade-off). HTTP-only: it does
// not run a DNS listener, so DNS-only exfiltration is out of scope by design.

'use strict';

const http = require('http');
const crypto = require('crypto');

/** The correlation id is the first path segment, if it looks like one. */
function extractCid(pathname) {
  const seg = String(pathname || '').split('/').filter(Boolean)[0] || '';
  return /^[a-z0-9]{6,40}$/i.test(seg) ? seg.toLowerCase() : '';
}

/** Mint a fresh, unguessable correlation id. */
function mintCid() {
  return crypto.randomBytes(8).toString('hex');
}

/** Bounded in-memory registry: cid → interaction[]. */
function createRegistry({ maxPerCid = 50, maxCids = 500 } = {}) {
  return { map: new Map(), maxPerCid, maxCids };
}

/** Pre-register a cid so polling returns [] (tracked) rather than nothing. */
function registerCid(reg, cid) {
  if (!cid) return;
  if (!reg.map.has(cid)) {
    if (reg.map.size >= reg.maxCids) reg.map.delete(reg.map.keys().next().value);
    reg.map.set(cid, []);
  }
}

/** Record one inbound interaction under its cid. Returns true when stored. */
function recordInteraction(reg, cid, meta) {
  if (!cid) return false;
  registerCid(reg, cid);
  const list = reg.map.get(cid);
  list.push(meta);
  if (list.length > reg.maxPerCid) list.shift();
  return true;
}

/** All interactions recorded for a cid (copy). */
function pollInteractions(reg, cid) {
  return (reg.map.get(cid) || []).slice();
}

/** HTTP catcher wrapping the pure registry above. */
class OobCatcher {
  constructor(opts = {}) {
    this.reg = createRegistry(opts);
    this.server = null;
  }

  mint() {
    const cid = mintCid();
    registerCid(this.reg, cid);
    return cid;
  }

  poll(cid) {
    return pollInteractions(this.reg, cid);
  }

  start({ port, host }) {
    this.server = http.createServer((req, res) => {
      let pathname = req.url;
      try { pathname = new URL(req.url, 'http://oob').pathname; } catch (_) {}
      const cid = extractCid(pathname);
      recordInteraction(this.reg, cid, {
        ts: new Date().toISOString(),
        method: req.method,
        path: pathname,
        host: req.headers.host || '',
        ua: req.headers['user-agent'] || '',
        remote: (req.socket && req.socket.remoteAddress) || '',
      });
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('ok');
    });
    return new Promise((resolve) => this.server.listen(port, host, resolve));
  }

  stop() {
    if (this.server) {
      try { this.server.close(); } catch (_) {}
      this.server = null;
    }
  }
}

module.exports = {
  extractCid,
  mintCid,
  createRegistry,
  registerCid,
  recordInteraction,
  pollInteractions,
  OobCatcher,
};
