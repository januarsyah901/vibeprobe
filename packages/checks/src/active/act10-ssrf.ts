import { type Check, type Finding } from '@vibeprobe/core';
import { injectionPoints, marker, sendInput, sleep } from './util';

const URL_PARAM = /^(url|uri|link|src|source|target|dest|image|img|fetch|proxy|webhook|callback|feed|site|u)$/i;

/**
 * Hands the app a URL that points at a listener inside vibeprobe (127.0.0.1). If the app's SERVER then
 * calls it, the hit is proof of SSRF. Nothing outside your machine is ever contacted.
 */
export const act10: Check = {
  id: 'ACT-10',
  title: 'Server-side request forgery (SSRF)',
  severity: 'critical',
  mode: 'active',
  intensity: 'full',
  async run({ client, surface, canary }) {
    if (!canary) return [];
    const findings: Finding[] = [];
    for (const point of injectionPoints(surface, 30).filter((p) => URL_PARAM.test(p.param)).slice(0, 6)) {
      const token = marker();
      const { request, curl, res } = await sendInput(client, point, canary.urlFor(token));
      for (let i = 0; i < 6 && canary.hits(token).length === 0; i++) await sleep(100);
      if (canary.hits(token).length === 0) continue;
      const path = new URL(point.url).pathname;
      findings.push({
        checkId: 'ACT-10',
        title: `The "${point.param}" input on ${path} makes your server fetch any address`,
        severity: 'critical',
        confidence: 'high',
        url: point.url,
        why: 'The server called the address we gave it. An attacker can use that to reach things only your server can see: internal services, cloud credentials, databases.',
        evidence: { request, status: res.status, excerpt: 'the test address (a listener on your own machine) was fetched by the server' },
        reproduce: curl,
        fixPrompt:
          `The "${point.param}" input on ${path} makes the server request the URL it is given. Please:\n` +
          `1. Only fetch URLs from an allowlist of exact hosts. Reject everything else.\n` +
          `2. Block private and loopback addresses (127.0.0.0/8, 10/8, 172.16/12, 192.168/16, 169.254/16, ::1), resolve the hostname first and check the IP, and do not follow redirects.\n` +
          `3. Allow only http and https.\n` +
          `Then run: npx vibeprobe ${surface.origin} --active=full --recheck ACT-10`,
      });
    }
    return findings;
  },
};
