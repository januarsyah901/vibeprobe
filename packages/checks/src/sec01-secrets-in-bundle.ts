import { curlFor, maskSecret, type Check, type Finding } from '@vibeprobe/core';
import { SECRET_PATTERNS } from './secret-patterns';

export const sec01: Check = {
  id: 'SEC-01',
  title: 'Secret exposed in JavaScript bundle',
  severity: 'critical',
  async run({ surface }) {
    const findings: Finding[] = [];
    for (const script of surface.scripts) {
      for (const p of SECRET_PATTERNS) {
        for (const m of script.body.matchAll(p.re)) {
          if (p.accept && !p.accept(m[0])) continue;
          const masked = p.name === 'Private key' ? '-----BEGIN PRIVATE KEY----- ****' : maskSecret(m[0]);
          findings.push({
            checkId: 'SEC-01',
            title: `${p.name} is sent to every visitor's browser`,
            severity: 'critical',
            confidence: 'high',
            url: script.url,
            why: `Anyone who opens the site can read this ${p.name.toLowerCase()} in the page's JavaScript and use it as you. Treat it as already stolen.`,
            evidence: { request: `GET ${script.url}`, status: 200, excerpt: masked },
            reproduce: `${curlFor(script.url)} | grep -c '${m[0].slice(0, 6)}'`,
            fixPrompt:
              `In this project a ${p.name} ends up in the JavaScript that is sent to the browser (found in ${new URL(script.url).pathname}). Please:\n` +
              `1. Find every use of that key and move it to server-only code (an API route or server action). Never use it in a client component.\n` +
              `2. Make sure its environment variable does not start with ${surface.framework === 'vite' ? 'VITE_' : surface.framework === 'nextjs' ? 'NEXT_PUBLIC_' : 'NEXT_PUBLIC_ or VITE_'}, because that prefix ships the value to the browser.\n` +
              `3. Treat the old key as leaked: create a new one in the provider's dashboard, revoke the old one, and replace it everywhere.\n` +
              `Then run: npx vibeprobe ${surface.origin} --recheck SEC-01`,
          });
          break; // one finding per pattern per file is enough
        }
      }
    }
    return findings;
  },
};
