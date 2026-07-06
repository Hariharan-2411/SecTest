// Notification formatting — pure, unit-testable (no chrome.*/network).
//
// Turns "interesting change" events into (1) a short human message for a local
// Chrome notification and (2) a platform-shaped webhook body for Telegram /
// Discord / Slack. The background worker decides WHEN to notify (deltas only,
// §7 of the plan); these helpers decide WHAT the message looks like.

export const WEBHOOK_PLATFORMS = ['discord', 'slack', 'telegram'];

/** Compact one-line title for a JS-change alert on a host. */
export function formatJsAlertTitle(host, diffCount) {
  const n = diffCount || 0;
  return `JS change on ${host || 'target'} — ${n} file(s) with new surface`;
}

/**
 * Multi-line body describing per-file diffs.
 * @param {string} host
 * @param {Array} diffs  array of jsdiff summaries: { url, summary, addedEndpoints }
 */
export function formatJsAlertBody(host, diffs = []) {
  const lines = [`Target: ${host || 'unknown'}`];
  for (const d of Array.isArray(diffs) ? diffs.slice(0, 10) : []) {
    lines.push(`• ${shortUrl(d.url)} — ${d.summary}`);
    for (const ep of (d.addedEndpoints || []).slice(0, 5)) lines.push(`    + ${ep}`);
  }
  return lines.join('\n');
}

function shortUrl(url) {
  try {
    const u = new URL(url);
    return u.pathname.split('/').pop() || u.hostname;
  } catch (_) {
    return String(url || '').slice(-40);
  }
}

/**
 * Build a webhook request body for the given platform.
 * @returns {{ body: object }} JSON body to POST (caller supplies the URL/headers)
 */
export function buildWebhookPayload(platform, title, body) {
  const text = `**${title}**\n${body}`;
  switch (platform) {
    case 'slack':
      return { body: { text: `*${title}*\n${body}`.slice(0, 3900) } }; // Slack ~4k limit
    case 'telegram':
      // Caller appends ?chat_id=... ; Telegram expects { text }. 4096-char cap.
      return { body: { text: `${title}\n${body}`.slice(0, 4000), parse_mode: 'Markdown' } };
    case 'discord':
    default:
      return { body: { content: text.slice(0, 1900) } }; // Discord 2000-char cap
  }
}

/** Should we fire a notification given user settings + whether anything is interesting? */
export function shouldNotify({ enabled = true, hasInteresting = false } = {}) {
  return Boolean(enabled && hasInteresting);
}
