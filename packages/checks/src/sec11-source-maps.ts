import { curlFor, type Check, type Finding } from '@vibeprobe/core';

export const sec11: Check = {
  id: 'SEC-11',
  title: 'Source maps exposed',
  severity: 'medium',
  async run({ client, surface }) {
    // Dev servers always serve source maps; only a production build makes this a real finding.
    if (surface.isDevServer) return [];
    const findings: Finding[] = [];
    for (const script of surface.scripts.slice(0, 15)) {
      const mapUrl = script.url + '.map';
      const res = await client.request(mapUrl);
      const type = res.headers.get('content-type') ?? '';
      if (res.status !== 200 || type.includes('text/html')) continue;
      if (!/"sources"\s*:/.test(res.body) || !/"mappings"\s*:/.test(res.body)) continue;
      findings.push({
        checkId: 'SEC-11',
        title: 'Your original source code can be downloaded',
        severity: 'medium',
        confidence: 'high',
        url: mapUrl,
        why: 'Source maps rebuild your readable source code from the shipped bundle. Anyone can study it to find weak spots and hardcoded values.',
        evidence: { request: `GET ${mapUrl}`, status: 200, excerpt: res.body.slice(0, 120).replace(/\s+/g, ' ') + ' ...' },
        reproduce: curlFor(mapUrl) + ' | head -c 200',
        fixPrompt:
          `Production source maps (.map files) are publicly downloadable. Please turn them off in the production build ` +
          `(Next.js: productionBrowserSourceMaps: false, Vite: build.sourcemap: false), or upload them to an error tracker and do not deploy them. ` +
          `Remove the existing .map files from the deployed output.\n` +
          `Then run: npx vibeprobe ${surface.origin} --recheck SEC-11`,
      });
      break; // one finding is enough: it is the same setting for every file
    }
    return findings;
  },
};
