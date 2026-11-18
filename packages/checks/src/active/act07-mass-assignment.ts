import { type Check, type Finding } from '@vibeprobe/core';
import { marker, ok, parseJson, protectedWrites, sendJson } from './util';

const PRIVILEGED = ['role', 'isAdmin', 'is_admin', 'admin'];

function echoed(value: unknown, depth = 0): string | undefined {
  if (depth > 3 || value === null || typeof value !== 'object') return undefined;
  if (Array.isArray(value)) return value.slice(0, 5).map((v) => echoed(v, depth + 1)).find(Boolean);
  const o = value as Record<string, unknown>;
  for (const k of PRIVILEGED) {
    if (o[k] === 'admin' || o[k] === true) return k;
  }
  return Object.values(o).map((v) => echoed(v, depth + 1)).find(Boolean);
}

/** Adds fields a normal user must never set (role, isAdmin) and looks for them in the answer. Uses marker values. */
export const act07: Check = {
  id: 'ACT-07',
  title: 'Mass assignment',
  severity: 'high',
  mode: 'active',
  intensity: 'full',
  async run({ client, surface }) {
    const findings: Finding[] = [];
    for (const ep of protectedWrites(surface, 6)) {
      const m = marker();
      const { res, request, curl } = await sendJson(client, ep, {
        name: `vp-${m}`,
        email: `vp-${m}@example.invalid`,
        role: 'admin',
        isAdmin: true,
        is_admin: true,
        admin: true,
      });
      if (!ok(res)) continue;
      const key = echoed(parseJson(res.body));
      if (!key) continue;
      const path = new URL(ep.url).pathname;
      findings.push({
        checkId: 'ACT-07',
        title: `${path} accepts fields it should never take from a visitor ("${key}")`,
        severity: 'high',
        confidence: 'medium',
        url: ep.url,
        why: 'We added a field that grants admin rights to a normal request and the server took it. An attacker can make themselves an admin, or change prices and ownership, by adding fields.',
        evidence: { request, status: res.status, excerpt: `the response contains ${key} set to the value we sent` },
        reproduce: curl,
        fixPrompt:
          `The endpoint ${ep.method} ${path} copies fields from the request body straight into the record (the "${key}" field was accepted). Please:\n` +
          `1. Pick the allowed fields explicitly (name, email, ...) and ignore everything else. Never spread req.body into a database call.\n` +
          `2. Set role, admin flags, price and owner on the server only.\n` +
          `Then run: npx vibeprobe ${surface.origin} --active=full --recheck ACT-07`,
      });
    }
    return findings;
  },
};
