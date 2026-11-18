import { curlFor, type Check, type Finding } from '@vibeprobe/core';

const EVIL_HOST = 'vibeprobe-host-test.example';
const PATHS = ['/', '/reset', '/forgot-password', '/password-reset', '/login'];

/** Sends a made-up Host / X-Forwarded-Host and looks for it in the page or the headers (password-reset poisoning). */
export const act11: Check = {
  id: 'ACT-11',
  title: 'Host header injection',
  severity: 'medium',
  mode: 'active',
  intensity: 'light',
  async run({ client, surface }) {
    const findings: Finding[] = [];
    for (const path of PATHS) {
      const url = new URL(path, surface.origin).href;
      const headers = { 'x-forwarded-host': EVIL_HOST, host: EVIL_HOST };
      const res = await client.request(url, { headers, followRedirects: false });
      if (res.status < 200 || res.status >= 400) continue;
      const inHeaders = [...res.headers.entries()].some(([, v]) => v.includes(EVIL_HOST));
      if (!inHeaders && !res.body.includes(EVIL_HOST)) continue;
      findings.push({
        checkId: 'ACT-11',
        title: `${path} builds links from a Host header the visitor controls`,
        severity: 'medium',
        confidence: 'high',
        url,
        why: 'The app printed the made-up host name we sent into its page or headers. If it does the same in password-reset emails, an attacker can make the reset link point to their own site.',
        evidence: { request: `GET ${url} with Host: ${EVIL_HOST}`, status: res.status, excerpt: `${EVIL_HOST} appears in the ${inHeaders ? 'response headers' : 'page'}` },
        reproduce: curlFor(url, headers),
        fixPrompt:
          `The app uses the request's Host (or X-Forwarded-Host) header to build absolute links. Please:\n` +
          `1. Take the public base URL from configuration (an environment variable like APP_URL), never from request headers.\n` +
          `2. Only trust X-Forwarded-Host when the app is behind your own proxy, and validate it against an allowlist.\n` +
          `Then run: npx vibeprobe ${surface.origin} --active --recheck ACT-11`,
      });
      break;
    }
    return findings;
  },
};
