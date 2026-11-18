import { curlFor, type Check, type Finding } from '@vibeprobe/core';
import { findPiiKeys } from '../sec03-unauthenticated-api';
import { isJson, marker, parseJson } from './util';

const PATHS = [
  '/api/admin', '/api/admin/users', '/api/v1/admin', '/api/v1/users', '/api/v1/config', '/api/config', '/api/internal',
  '/api/debug', '/api/export', '/api/logs', '/api/keys', '/api/secrets', '/api/env', '/api/backup', '/api/users/export',
  '/admin/api', '/admin/users', '/internal', '/debug', '/_debug', '/backup', '/api/v2/admin', '/api/private',
];
const SENSITIVE_PATH = /(admin|config|secret|env|keys|backup|internal|debug|private|export)/i;

/** GET-only guessing of common hidden routes. A 200 JSON answer that differs from a random 404 counts. */
export const act12: Check = {
  id: 'ACT-12',
  title: 'Hidden route answers without login',
  severity: 'high',
  mode: 'active',
  intensity: 'light',
  async run({ client, surface }) {
    const findings: Finding[] = [];
    const baseline = await client.request(new URL(`/vibeprobe-fb-${marker()}`, surface.origin).href);
    for (const path of PATHS) {
      const url = new URL(path, surface.origin).href;
      const res = await client.request(url);
      if (res.status !== 200 || !isJson(res) || res.body === baseline.body) continue;
      const data = parseJson(res.body);
      if (data === undefined || data === null || (typeof data === 'object' && Object.keys(data as object).length === 0)) continue;
      const pii = [...findPiiKeys(data)];
      const severity = pii.length > 0 || SENSITIVE_PATH.test(path) ? 'high' : 'medium';
      findings.push({
        checkId: 'ACT-12',
        title: `${path} exists and answers with data, no login needed`,
        severity,
        confidence: 'high',
        url,
        why: 'This route is not linked anywhere, but a guess found it, and it answered an anonymous request with data. Hidden is not the same as protected.',
        evidence: { request: `GET ${url} (no cookies, no token)`, status: 200, excerpt: pii.length > 0 ? `response contains fields: ${pii.join(', ')}` : 'response contains data (values not shown)' },
        reproduce: curlFor(url),
        fixPrompt:
          `The route ${path} answers anonymous requests with data. Please:\n` +
          `1. Require a valid session or token on the server and answer 401 to anonymous callers. Also check the caller's role for admin routes.\n` +
          `2. If the route is not needed, delete it.\n` +
          `Then run: npx vibeprobe ${surface.origin} --active --recheck ACT-12`,
      });
    }
    return findings;
  },
};
