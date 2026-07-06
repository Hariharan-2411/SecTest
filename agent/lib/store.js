// Tiny JSON persistence for watches so they survive agent restarts. Writes
// atomically (temp file + rename) so a crash mid-write can't corrupt the store.
// The data dir is mounted as a Docker volume (see docker-compose.yml).

'use strict';

const fs = require('fs');
const path = require('path');

const DATA_DIR = process.env.AGENT_DATA_DIR || path.join(__dirname, '..', 'data');
const WATCHES_FILE = path.join(DATA_DIR, 'watches.json');

function ensureDir() {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  } catch (_) {}
}

/** Load the watches array; returns [] on missing/corrupt file. */
function loadWatches() {
  try {
    const raw = fs.readFileSync(WATCHES_FILE, 'utf8');
    const data = JSON.parse(raw);
    return Array.isArray(data) ? data : [];
  } catch (_) {
    return [];
  }
}

/** Persist the watches array atomically. */
function saveWatches(watches) {
  ensureDir();
  const tmp = WATCHES_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(watches || [], null, 2));
  fs.renameSync(tmp, WATCHES_FILE);
}

module.exports = { DATA_DIR, WATCHES_FILE, loadWatches, saveWatches };
