import { describe, it, expect } from '@jest/globals';
import { fingerprintStack, formatFingerprint } from '../src/utils/fingerprint';

describe('fingerprintStack — tech signals → the right tool', () => {
  it('maps a WordPress path to wpscan, scoped to its host', () => {
    const fp = fingerprintStack({ surface: { urls: ['https://blog.example.com/wp-login.php'] } });
    const wp = fp.suggestions.find((s) => /wordpress/i.test(s.tech));
    expect(wp).toBeTruthy();
    expect(wp.tools).toContain('wpscan');
    expect(wp.host).toBe('blog.example.com');
  });

  it('maps a /graphql endpoint and a parametered URL to their tools', () => {
    const fp = fingerprintStack({
      surface: { urls: ['https://api.example.com/graphql', 'https://api.example.com/item?id=3'] },
    });
    expect(fp.suggestions.some((s) => /graphql/i.test(s.tech))).toBe(true);
    const param = fp.suggestions.find((s) => /param/i.test(s.tech));
    expect(param.tools).toEqual(expect.arrayContaining(['sqlmap', 'dalfox']));
  });

  it('maps finding TYPES to tools (jwt → jwt_tool, takeover → subzy)', () => {
    const fp = fingerprintStack({
      findings: [
        { type: 'jwt', host: 'app.example.com' },
        { type: 'subdomain-takeover', host: 'old.example.com' },
      ],
    });
    expect(fp.suggestions.find((s) => /jwt/i.test(s.tech)).tools).toContain('jwt_tool');
    expect(fp.suggestions.find((s) => /takeover/i.test(s.tech)).tools).toContain('subzy');
  });

  it('never throws on garbage and returns empty suggestions', () => {
    expect(() => fingerprintStack(null)).not.toThrow();
    expect(fingerprintStack({}).suggestions).toEqual([]);
    expect(formatFingerprint(null)).toBe('');
  });

  it('formats a compact one-line hint for the planner', () => {
    const fp = fingerprintStack({ surface: { urls: ['https://blog.example.com/wp-admin/'] } });
    const line = formatFingerprint(fp);
    expect(line).toMatch(/wordpress/i);
    expect(line).toMatch(/wpscan/);
  });
});
