import { curlFor, maskSecret, type Check, type Finding } from '@vibeprobe/core';
import { SECRET_PATTERNS } from './secret-patterns';

export const sec13: Check = {
  id: 'SEC-13',
  title: 'Secret returned by an API endpoint',
  severity: 'critical',
  async run({ client, surface }) {
    const findings: Finding[] = [];
    for (const url of surface.endpoints.slice(0, 25)) {
      const res = await client.request(url);
      const type = res.headers.get('content-type') ?? '';
      if (res.status !== 200 || type.includes('html')) continue;
      for (const p of SECRET_PATTERNS) {
        const m = [...res.body.matchAll(p.re)].find((x) => !p.accept || p.accept(x[0]));
        if (!m) continue;
        const path = new URL(url).pathname;
        findings.push({
          checkId: 'SEC-13',
          title: `${p.name} is returned by ${path}`,
          severity: 'critical',
          confidence: 'high',
          url,
          why: `Anyone can call this endpoint without logging in and read a ${p.name.toLowerCase()} in the answer. Treat it as already stolen.`,
          evidence: {
            request: `GET ${url} (no cookies, no token)`,
            status: 200,
            excerpt: p.name === 'Private key' ? '-----BEGIN PRIVATE KEY----- ****' : maskSecret(m[0]),
          },
          reproduce: `${curlFor(url)} | grep -c '${m[0].slice(0, 6)}'`,
          fixPrompt:
            `The endpoint ${path} returns a ${p.name} in its response to anonymous callers. Please:\n` +
            `1. Remove the secret from the response. Return only what the browser really needs.\n` +
            `2. Keep the secret in server-only code and environment variables.\n` +
            `3. Treat the old secret as leaked: create a new one at the provider, revoke the old one, and replace it everywhere.\n` +
            `Then run: npx vibeprobe ${surface.origin} --recheck SEC-13`,
        });
        break;
      }
    }
    return findings;
  },
};
