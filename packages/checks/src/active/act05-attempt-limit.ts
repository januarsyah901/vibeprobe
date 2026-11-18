import { type Check, type Finding } from '@vibeprobe/core';
import { loginEndpoints, sendJson } from './util';

const ATTEMPTS = 12;

/**
 * Sends a small burst of wrong logins (never a guess list) and checks whether anything pushes back:
 * a 429/423 status, a Retry-After header or a rate-limit header. This is not password guessing.
 */
export const act05: Check = {
  id: 'ACT-05',
  title: 'Login has no attempt limit',
  severity: 'medium',
  mode: 'active',
  intensity: 'full',
  async run({ client, surface }) {
    const findings: Finding[] = [];
    for (const ep of loginEndpoints(surface)) {
      let pushedBack = false;
      let usable = false;
      let last;
      for (let i = 0; i < ATTEMPTS; i++) {
        last = await sendJson(client, ep, { email: 'vibeprobe@example.invalid', username: 'vibeprobe', password: `wrong-${i}` });
        const { res } = last;
        if (res.status !== 404 && res.status !== 405 && res.status < 500) usable = true;
        if (res.status === 429 || res.status === 423 || res.headers.has('retry-after') || [...res.headers.keys()].some((k) => /^(x-)?ratelimit/i.test(k))) {
          pushedBack = true;
          break;
        }
      }
      if (pushedBack || !usable || !last) continue;
      const path = new URL(ep.url).pathname;
      findings.push({
        checkId: 'ACT-05',
        title: `${path} lets anyone try wrong passwords again and again`,
        severity: 'medium',
        confidence: 'medium',
        url: ep.url,
        why: `${ATTEMPTS} wrong attempts in a row were all answered normally: no 429, no lock, no delay. That makes guessing passwords or one-time codes practical.`,
        evidence: { request: `${ATTEMPTS} × ${last.request.split(' body:')[0]} with wrong credentials`, status: last.res.status, excerpt: 'no 429, no Retry-After, no rate-limit header' },
        reproduce: last.curl,
        fixPrompt:
          `The endpoint ${path} accepted ${ATTEMPTS} wrong login attempts in a row without slowing down. Please:\n` +
          `1. Add rate limiting per IP and per account on login, password reset and code-verification endpoints (for example 5 attempts per 15 minutes), answering 429 with a Retry-After header.\n` +
          `2. Add a growing delay or a temporary lock after repeated failures.\n` +
          `Then run: npx vibeprobe ${surface.origin} --active=full --recheck ACT-05`,
      });
    }
    return findings;
  },
};
