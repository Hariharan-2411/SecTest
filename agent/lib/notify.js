// Webhook notification formatting for the agent scheduler — mirrors the
// extension's notify.js so alerts look the same whichever side sends them.
// Pure formatting; the server does the actual POST.

'use strict';

/** One-line title for a watch delta. */
function formatWatchTitle(target, addedTotal) {
  return `New recon surface on ${target || 'target'} — +${addedTotal || 0} item(s)`;
}

/** Multi-line body listing what's new per category. */
function formatWatchBody(target, delta) {
  const lines = [`Target: ${target || 'unknown'}`];
  const added = (delta && delta.added) || {};
  for (const cat of Object.keys(added)) {
    const items = added[cat] || [];
    if (!items.length) continue;
    lines.push(`${cat} (+${items.length}):`);
    for (const it of items.slice(0, 8)) lines.push(`  + ${itemLabel(cat, it)}`);
  }
  return lines.join('\n');
}

function itemLabel(cat, it) {
  if (typeof it === 'string') return it;
  if (cat === 'http') return `${it.status || ''} ${it.url || ''}`.trim();
  if (cat === 'ports') return `${it.host || ''}:${it.port || ''}`;
  if (cat === 'findings') return `[${it.severity || 'info'}] ${it.name || it.templateId || ''} ${it.matched || ''}`.trim();
  return JSON.stringify(it);
}

/** Build a platform-shaped webhook body (Discord/Slack/Telegram). */
function buildWebhookPayload(platform, title, body) {
  switch (platform) {
    case 'slack':
      return { text: `*${title}*\n${body}`.slice(0, 3900) };
    case 'telegram':
      return { text: `${title}\n${body}`.slice(0, 4000), parse_mode: 'Markdown' };
    case 'discord':
    default:
      return { content: `**${title}**\n${body}`.slice(0, 1900) };
  }
}

module.exports = { formatWatchTitle, formatWatchBody, buildWebhookPayload, itemLabel };
