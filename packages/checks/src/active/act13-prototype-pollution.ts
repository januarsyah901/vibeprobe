import { type Check, type Finding } from '@vibeprobe/core';
import { marker, ok, parseJson, protectedWrites } from './util';

/** True if `needle` shows up as a value anywhere except under a "__proto__" or "constructor" key (those are just our echo). */
function appears(value: unknown, needle: string, depth = 0): boolean {
  if (depth > 5) return false;
  if (typeof value === 'string') return value === needle;
  if (value === null || typeof value !== 'object') return false;
  return Object.entries(value).some(([k, v]) => k !== '__proto__' && k !== 'constructor' && appears(v, needle, depth + 1));
}

/**
 * Sends {"__proto__": {"vpPolluted": <marker>}} and checks whether the marker comes back as a value the app
 * did not put there. It only touches the app's in-memory objects: a restart clears it. Full mode only.
 */
export const act13: Check = {
  id: 'ACT-13',
  title: 'Prototype pollution',
  severity: 'high',
  mode: 'active',
  intensity: 'full',
  async run({ client, surface }) {
    const findings: Finding[] = [];
    for (const ep of protectedWrites(surface, 6)) {
      const m = marker();
      // Raw text on purpose: JSON.stringify would silently drop a "__proto__" key.
      for (const sent of [`{"__proto__":{"vpPolluted":"${m}"}}`, `{"constructor":{"prototype":{"vpPolluted":"${m}"}}}`]) {
        const res = await client.request(ep.url, { method: ep.method, headers: { 'content-type': 'application/json' }, body: sent });
        if (!ok(res) || !appears(parseJson(res.body), m)) continue;
        const path = new URL(ep.url).pathname;
        findings.push({
          checkId: 'ACT-13',
          title: `${path} lets a request change every object in your app (prototype pollution)`,
          severity: 'high',
          confidence: 'high',
          url: ep.url,
          why: 'A "__proto__" key in the request body changed shared state inside the app. Attackers use this to bypass checks, crash the app, or sometimes run code.',
          evidence: { request: `${ep.method} ${ep.url} body: ${sent}`, status: res.status, excerpt: 'the marker value came back from an object that should not have it' },
          reproduce: `curl -sS -i -X ${ep.method} -H 'content-type: application/json' --data-raw '${sent}' '${ep.url}'`,
          fixPrompt:
            `The endpoint ${ep.method} ${path} merges the request body into objects in a way that lets "__proto__" or "constructor" keys change Object.prototype. Please:\n` +
            `1. Do not deep-merge untrusted JSON. Copy only known fields.\n` +
            `2. If a merge helper is needed, use a patched one that skips "__proto__", "constructor" and "prototype", and update lodash/merge-style packages.\n` +
            `3. Create lookup objects with Object.create(null) or a Map.\n` +
            `Then run: npx vibeprobe ${surface.origin} --active=full --recheck ACT-13`,
        });
        break;
      }
    }
    return findings;
  },
};
