import { curlFor, type Check } from '@vibeprobe/core';

const EVIL = 'https://vibeprobe-origin-test.example';

export const sec08: Check = {
  id: 'SEC-08',
  title: 'CORS reflects any origin with credentials',
  severity: 'high',
  async run({ client, surface }) {
    const targets = [surface.home.url, ...surface.endpoints.slice(0, 10)];
    for (const url of targets) {
      const res = await client.request(url, { headers: { Origin: EVIL } });
      const allowOrigin = res.headers.get('access-control-allow-origin');
      const allowCreds = res.headers.get('access-control-allow-credentials');
      if (allowOrigin === EVIL && allowCreds?.toLowerCase() === 'true') {
        return [
          {
            checkId: 'SEC-08',
            title: 'Any website can read responses on behalf of a logged-in user',
            severity: 'high',
            confidence: 'high',
            url,
            why: 'The server answers a made-up origin with "allowed, with cookies". A malicious page could then read your users\' private data while they are logged in.',
            evidence: {
              request: `GET ${url} with Origin: ${EVIL}`,
              status: res.status,
              excerpt: `access-control-allow-origin: ${allowOrigin}\naccess-control-allow-credentials: ${allowCreds}`,
            },
            reproduce: curlFor(url, { Origin: EVIL }) + ' | grep -i access-control',
            fixPrompt:
              `This app's CORS setup echoes back any Origin header and also sends Access-Control-Allow-Credentials: true. Please:\n` +
              `1. Replace the "reflect the request origin" logic with a fixed allowlist of the exact origins that should have access.\n` +
              `2. Never combine a wildcard or reflected origin with credentials.\n` +
              `Then run: npx vibeprobe ${surface.origin} --recheck SEC-08`,
          },
        ];
      }
    }
    return [];
  },
};
