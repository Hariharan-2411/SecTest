import { describe, it, expect } from '@jest/globals';
import {
  formatJsAlertTitle,
  formatJsAlertBody,
  buildWebhookPayload,
  shouldNotify,
  WEBHOOK_PLATFORMS,
} from '../src/utils/notify';

describe('formatJsAlertTitle', () => {
  it('includes host and count', () => {
    expect(formatJsAlertTitle('app.example.com', 2)).toBe(
      'JS change on app.example.com — 2 file(s) with new surface'
    );
  });
});

describe('formatJsAlertBody', () => {
  it('lists files and their added endpoints', () => {
    const body = formatJsAlertBody('x.com', [
      { url: 'https://x.com/static/app.js', summary: '+1 endpoint(s)', addedEndpoints: ['/api/new'] },
    ]);
    expect(body).toContain('Target: x.com');
    expect(body).toContain('app.js');
    expect(body).toContain('+ /api/new');
  });
});

describe('buildWebhookPayload', () => {
  it('uses content for discord', () => {
    const { body } = buildWebhookPayload('discord', 'Title', 'Body');
    expect(body.content).toContain('Title');
  });
  it('uses text for slack', () => {
    expect(buildWebhookPayload('slack', 'T', 'B').body.text).toContain('T');
  });
  it('uses text + parse_mode for telegram', () => {
    const { body } = buildWebhookPayload('telegram', 'T', 'B');
    expect(body.text).toContain('T');
    expect(body.parse_mode).toBe('Markdown');
  });
  it('caps discord content length', () => {
    const { body } = buildWebhookPayload('discord', 'T', 'x'.repeat(5000));
    expect(body.content.length).toBeLessThanOrEqual(1900);
  });
});

describe('shouldNotify', () => {
  it('fires only when enabled and something is interesting', () => {
    expect(shouldNotify({ enabled: true, hasInteresting: true })).toBe(true);
    expect(shouldNotify({ enabled: false, hasInteresting: true })).toBe(false);
    expect(shouldNotify({ enabled: true, hasInteresting: false })).toBe(false);
  });
});

describe('constants', () => {
  it('exposes supported platforms', () => {
    expect(WEBHOOK_PLATFORMS).toEqual(expect.arrayContaining(['discord', 'slack', 'telegram']));
  });
});
