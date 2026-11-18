import { curlFor, type Check, type Finding } from '@vibeprobe/core';

const EVIL = 'https://vibeprobe-redirect-test.example';
const REDIRECT_PARAM = /^(next|redirect|redirect_?uri|redirect_?url|return|return_?to|return_?url|url|continue|dest|destination|goto|callback|to)$/i;
const CANDIDATE_PATHS = ['/login', '/logout', '/signin', '/redirect', '/go', '/out', '/auth/callback'];
const CANDIDATE_PARAMS = ['next', 'redirect', 'url', 'return_to'];

export const sec15: Check = {
  id: 'SEC-15',
  title: 'Open redirect',
  severity: 'medium',
  async run({ client, surface }) {
    const targets = new Map<string, { url: string; param: string }>();
    for (const p of surface.params) if (REDIRECT_PARAM.test(p.name)) targets.set(`${p.url}|${p.name}`, { url: p.url, param: p.name });
    for (const f of surface.forms) {
      if (f.method === 'GET') for (const name of f.fields) if (REDIRECT_PARAM.test(name)) targets.set(`${f.action}|${name}`, { url: f.action, param: name });
    }
    const asks = async (probe: URL) => {
      const res = await client.request(probe, { followRedirects: false });
      const location = res.headers.get('location');
      if (res.status < 300 || res.status >= 400 || !location) return undefined;
      try {
        return new URL(location, probe).origin === EVIL ? { res, location } : undefined;
      } catch {
        return undefined;
      }
    };
    const findings: Finding[] = [];
    const reported = new Set<string>();
    const queue = [...targets.values()].slice(0, 30).map((t) => ({ ...t, guess: false }));
    // Common login/redirect paths get one request with every usual parameter; a hit is narrowed down afterwards.
    for (const path of CANDIDATE_PATHS) {
      const url = new URL(path, surface.origin).href;
      if (![...targets.values()].some((t) => t.url === url)) queue.push({ url, param: CANDIDATE_PARAMS[0]!, guess: true });
    }
    for (const entry of queue) {
      if (reported.has(entry.url)) continue;
      let param = entry.param;
      const probe = new URL(entry.url);
      let hit;
      if (entry.guess) {
        for (const p of CANDIDATE_PARAMS) probe.searchParams.set(p, EVIL);
        if (!(await asks(probe))) continue;
        probe.search = '';
        for (const p of CANDIDATE_PARAMS) {
          probe.searchParams.set(p, EVIL);
          hit = await asks(probe);
          if (hit) {
            param = p;
            break;
          }
          probe.search = '';
        }
        if (!hit) continue;
      } else {
        probe.searchParams.set(param, EVIL);
        hit = await asks(probe);
        if (!hit) continue;
      }
      const { res, location } = hit;
      const url = entry.url;
      reported.add(url);
      const path = new URL(url).pathname;
      findings.push({
        checkId: 'SEC-15',
        title: `${path} redirects visitors to any website (parameter "${param}")`,
        severity: 'medium',
        confidence: 'high',
        url: probe.href,
        why: 'An attacker can send your users a link that starts on your real domain and ends on a fake login page. People trust the first part of the address.',
        evidence: { request: `GET ${probe.href} (redirects not followed)`, status: res.status, excerpt: `location: ${location}` },
        reproduce: curlFor(probe.href) + ' | grep -i "^location"',
        fixPrompt:
          `The "${param}" parameter on ${path} makes the server redirect to any address, including other websites. Please:\n` +
          `1. Only redirect to paths on this site: accept values that start with a single "/" (not "//") and reject anything with a scheme or a different host.\n` +
          `2. Or keep an allowlist of exact destinations and redirect only to those.\n` +
          `Then run: npx vibeprobe ${surface.origin} --recheck SEC-15`,
      });
    }
    return findings;
  },
};
