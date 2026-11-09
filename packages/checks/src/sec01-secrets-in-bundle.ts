import { curlFor, maskSecret, type Check, type Finding } from '@vibeprobe/core';

interface Pattern {
  name: string;
  re: RegExp;
  /** Return false to ignore a match (e.g. a public key). */
  accept?: (match: string) => boolean;
}

function jwtRole(token: string): string | undefined {
  try {
    const payload = token.split('.')[1]!;
    return (JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as { role?: string }).role;
  } catch {
    return undefined;
  }
}

const PATTERNS: Pattern[] = [
  { name: 'Stripe secret key', re: /\bsk_live_[0-9A-Za-z]{16,}\b/g },
  { name: 'AWS access key ID', re: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: 'GitHub token', re: /\bgh[pousr]_[0-9A-Za-z]{30,}\b/g },
  { name: 'Private key', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g },
  { name: 'Slack token', re: /\bxox[abprs]-[0-9A-Za-z-]{20,}\b/g },
  {
    // Supabase anon keys are public by design: only the service_role key is a leak.
    name: 'Supabase service_role key',
    re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    accept: (m) => jwtRole(m) === 'service_role',
  },
];

export const sec01: Check = {
  id: 'SEC-01',
  title: 'Secret exposed in JavaScript bundle',
  severity: 'critical',
  async run({ surface }) {
    const findings: Finding[] = [];
    for (const script of surface.scripts) {
      for (const p of PATTERNS) {
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
