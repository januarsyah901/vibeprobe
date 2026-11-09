import { curlFor, maskEnvLines, type Check, type Finding } from '@vibeprobe/core';

interface Probe {
  path: string;
  label: string;
  /** Must match for the response to count: a 200 alone proves nothing (SPAs answer 200 to everything). */
  signature: RegExp;
  excerpt: (body: string) => string;
}

const PROBES: Probe[] = [
  {
    path: '/.env',
    label: 'Environment file (.env)',
    signature: /^[A-Z][A-Z0-9_]{2,}\s*=\s*\S+/m,
    excerpt: (b) => maskEnvLines(b),
  },
  {
    path: '/.git/HEAD',
    label: 'Git repository (.git/HEAD)',
    signature: /^ref:\s+refs\/heads\//,
    excerpt: (b) => b.trim().slice(0, 80),
  },
  {
    path: '/.git/config',
    label: 'Git config (.git/config)',
    signature: /^\[core\]/m,
    excerpt: (b) => b.split(/\r?\n/).slice(0, 4).join('\n').replace(/(url\s*=\s*https?:\/\/)[^@\s]+@/, '$1****@'),
  },
];

export const sec06: Check = {
  id: 'SEC-06',
  title: 'Sensitive file exposed',
  severity: 'critical',
  async run({ client, surface }) {
    const findings: Finding[] = [];
    for (const probe of PROBES) {
      const url = new URL(probe.path, surface.origin).href;
      const res = await client.request(url);
      const html = (res.headers.get('content-type') ?? '').includes('text/html');
      if (res.status !== 200 || html || !probe.signature.test(res.body)) continue;
      findings.push({
        checkId: 'SEC-06',
        title: `${probe.label} can be downloaded by anyone`,
        severity: 'critical',
        confidence: 'high',
        url,
        why:
          probe.path === '/.env'
            ? 'The file holds your passwords and API keys, and the web server hands it to anyone who asks.'
            : 'Anyone can download your project history from the web server, including code and sometimes secrets that were deleted later.',
        evidence: { request: `GET ${url}`, status: 200, excerpt: probe.excerpt(res.body) },
        reproduce: curlFor(url),
        fixPrompt:
          `The file ${probe.path} is publicly downloadable from this app. Please:\n` +
          `1. Make sure the web server only serves a dedicated public folder (for Next.js "public/", for Vite the "dist/" build output) and never the project root.\n` +
          `2. Add a rule that blocks requests for dotfiles (any path starting with ".") in the server or hosting config.\n` +
          (probe.path === '/.env'
            ? `3. Treat every value in that file as leaked: rotate all keys and passwords.\n`
            : `3. Remove the .git folder from the deployed files.\n`) +
          `Then run: npx vibeprobe ${surface.origin} --recheck SEC-06`,
      });
    }
    return findings;
  },
};
