import { curlWrite, type Check, type Finding } from '@vibeprobe/core';
import { ok, protectedWrites } from './util';

const EVIL_ORIGIN = 'https://vibeprobe-csrf-test.example';
const SESSION_NAME = /(sess|sid$|^sid|token|auth|jwt|login|connect\.sid)/i;

/**
 * Only runs when the app sets a login-style cookie WITHOUT SameSite (otherwise browsers already
 * stop cross-site posts). Then it asks: does a write endpoint accept a form post that says it came
 * from another website, with no token?
 */
export const act03: Check = {
  id: 'ACT-03',
  title: 'Cross-site request forgery (CSRF)',
  severity: 'medium',
  mode: 'active',
  intensity: 'light',
  async run({ client, surface }) {
    const exposed = surface.home.headers
      .getSetCookie()
      .map((c) => c.split(';').map((p) => p.trim()))
      .filter(([pair = '', ...attrs]) => SESSION_NAME.test(pair.split('=')[0] ?? '') && !attrs.some((a) => a.toLowerCase().startsWith('samesite=')));
    if (exposed.length === 0) return [];

    const findings: Finding[] = [];
    for (const ep of protectedWrites(surface, 6)) {
      const headers = { 'content-type': 'application/x-www-form-urlencoded', origin: EVIL_ORIGIN };
      const body = 'vibeprobe=csrf-test';
      const res = await client.request(ep.url, { method: ep.method, headers, body });
      if (!ok(res)) continue; // 401/403/4xx: something checked the request
      const path = new URL(ep.url).pathname;
      findings.push({
        checkId: 'ACT-03',
        title: `${path} accepts a form post that claims to come from another website`,
        severity: 'medium',
        confidence: 'medium',
        url: ep.url,
        why: 'The login cookie has no SameSite flag and this endpoint did not ask for a token or check where the request came from. A malicious page could make a logged-in visitor\'s browser change data on your app.',
        evidence: { request: `${ep.method} ${ep.url} with Origin: ${EVIL_ORIGIN}, no token`, status: res.status, excerpt: 'request accepted' },
        reproduce: curlWrite(ep.method, ep.url, { headers, body }),
        fixPrompt:
          `The endpoint ${path} changes data and accepted a cross-site form post with no CSRF token. Please:\n` +
          `1. Set the session cookie with SameSite=Lax (or Strict), HttpOnly and Secure.\n` +
          `2. Reject state-changing requests whose Origin or Referer is not this site, or require a CSRF token.\n` +
          `Then run: npx vibeprobe ${surface.origin} --active --recheck ACT-03`,
      });
    }
    return findings;
  },
};
