import { type Check, type Finding } from '@vibeprobe/core';
import { isJson, ok, protectedWrites, sendJson } from './util';

/**
 * Sends an EMPTY json body to endpoints that change data. A server that checks the login first answers
 * 401/403. One that answers 2xx, or complains about the missing fields (400/422), never asked who we are.
 */
export const act06: Check = {
  id: 'ACT-06',
  title: 'Data-changing endpoint works without login',
  severity: 'high',
  mode: 'active',
  intensity: 'full',
  async run({ client, surface }) {
    const findings: Finding[] = [];
    for (const ep of protectedWrites(surface)) {
      const { res, request, curl } = await sendJson(client, ep, {});
      const accepted = ok(res);
      const reachedValidation = (res.status === 400 || res.status === 422) && isJson(res);
      if (!accepted && !reachedValidation) continue;
      const path = new URL(ep.url).pathname;
      findings.push({
        checkId: 'ACT-06',
        title: `${path} accepts ${ep.method} requests from anyone, no login needed`,
        severity: 'high',
        confidence: accepted ? 'high' : 'medium',
        url: ep.url,
        why: accepted
          ? 'An anonymous, empty request was accepted. Anyone on the internet can add or change data through this endpoint (it may have left an empty record).'
          : 'An anonymous request got as far as the field checks instead of a 401. The endpoint looks at the data before it asks who you are, which usually means it never asks.',
        evidence: { request, status: res.status, excerpt: accepted ? 'request accepted' : `rejected only for its fields (${res.status}), not for missing login` },
        reproduce: curl,
        fixPrompt:
          `The endpoint ${ep.method} ${path} handles requests from anonymous callers (answered ${res.status} instead of 401). Please:\n` +
          `1. Check the session or token first, in a middleware or at the top of the handler, and answer 401 before reading the body.\n` +
          `2. Check the caller is allowed to change this record (ownership or role), and answer 403 if not.\n` +
          `3. If this endpoint is meant to be public (like a contact form), add rate limiting and validation instead.\n` +
          `Then run: npx vibeprobe ${surface.origin} --active=full --recheck ACT-06`,
      });
    }
    return findings;
  },
};
