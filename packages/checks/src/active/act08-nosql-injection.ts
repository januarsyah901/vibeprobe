import { type Check, type Finding } from '@vibeprobe/core';
import { loginEndpoints, ok, sendJson } from './util';

export const act08: Check = {
  id: 'ACT-08',
  title: 'NoSQL injection in login',
  severity: 'critical',
  mode: 'active',
  intensity: 'full',
  async run({ client, surface }) {
    const findings: Finding[] = [];
    for (const ep of loginEndpoints(surface)) {
      const wrong = await sendJson(client, ep, { username: 'vp-nobody', email: 'vp-nobody@example.invalid', password: 'vp-wrong' });
      if (ok(wrong.res)) continue; // a login that "works" with wrong credentials is a different problem
      const ne = { $ne: null };
      const { res, request, curl } = await sendJson(client, ep, { username: ne, email: ne, password: ne });
      if (!ok(res)) continue;
      const path = new URL(ep.url).pathname;
      findings.push({
        checkId: 'ACT-08',
        title: `${path} can be logged into without knowing a password`,
        severity: 'critical',
        confidence: 'high',
        url: ep.url,
        why: 'Wrong credentials are rejected, but sending {"$ne": null} instead of a password was accepted. Query operators in the input are run by the database, so an attacker can log in as any user.',
        evidence: { request, status: res.status, excerpt: `wrong password: ${wrong.res.status}; {"$ne": null}: ${res.status} (accepted)` },
        reproduce: curl,
        fixPrompt:
          `The login endpoint ${path} passes the request body straight into a database query, and {"$ne": null} logs in without a password. Please:\n` +
          `1. Check that username/email and password are plain strings (typeof === "string") before they go anywhere near the query. Reject objects and arrays with 400.\n` +
          `2. Use a schema validator (for example zod) on every request body.\n` +
          `3. For MongoDB, consider mongo-sanitize or setting sanitizeFilter.\n` +
          `Then run: npx vibeprobe ${surface.origin} --active=full --recheck ACT-08`,
      });
    }
    return findings;
  },
};
