import { curlFor, type Check, type Finding } from '@vibeprobe/core';

const PII_KEY = /^(e-?mail|phone|mobile|password|passwd|token|access_?token|secret|ssn|address|full_?name|user_?id|api_?key)$/i;
const PRIVATE_PATH = /\/(users?|accounts?|admins?|customers?|orders?|payments?|invoices?|profiles?|members?|messages?|me)(\/|$)/i;

/** Collects key names that look like personal data, walking at most a few levels. */
export function findPiiKeys(value: unknown, depth = 0, found = new Set<string>()): Set<string> {
  if (depth > 4 || value === null || typeof value !== 'object') return found;
  if (Array.isArray(value)) {
    for (const item of value.slice(0, 5)) findPiiKeys(item, depth + 1, found);
    return found;
  }
  for (const [k, v] of Object.entries(value)) {
    if (PII_KEY.test(k)) found.add(k);
    findPiiKeys(v, depth + 1, found);
  }
  return found;
}

export const sec03: Check = {
  id: 'SEC-03',
  title: 'API endpoint answers without authentication',
  severity: 'high',
  async run({ client, surface }) {
    const findings: Finding[] = [];
    for (const url of surface.endpoints.slice(0, 25)) {
      const res = await client.request(url);
      const type = res.headers.get('content-type') ?? '';
      if (res.status !== 200 || !type.includes('json')) continue;
      let data: unknown;
      try {
        data = JSON.parse(res.body);
      } catch {
        continue;
      }
      const empty = data === null || (Array.isArray(data) && data.length === 0) || (typeof data === 'object' && Object.keys(data as object).length === 0);
      if (empty) continue;

      const pii = [...findPiiKeys(data)];
      const path = new URL(url).pathname;
      // Many endpoints are public on purpose (/api/products). Only prove harm with personal-data fields;
      // an endpoint that merely *sounds* private is a low-confidence hint.
      let confidence: 'high' | 'low';
      if (pii.length > 0) confidence = 'high';
      else if (PRIVATE_PATH.test(path)) confidence = 'low';
      else continue;

      findings.push({
        checkId: 'SEC-03',
        title: `${path} returns data to anyone, no login needed`,
        severity: 'high',
        confidence,
        url,
        why:
          confidence === 'high'
            ? 'This endpoint answered a request without any cookie or token and the response contains personal data. Anyone on the internet can read it.'
            : 'This endpoint answered without any login and its name suggests private data. If it is meant to be public, ignore this; if not, anyone can read it.',
        evidence: {
          request: `GET ${url} (no cookies, no token)`,
          status: 200,
          excerpt: confidence === 'high' ? `response contains fields: ${pii.join(', ')}` : 'response contains data (values not shown)',
        },
        reproduce: curlFor(url),
        fixPrompt:
          `The endpoint ${path} returns data without checking who is asking. Please:\n` +
          `1. Require a valid session or token on the server for this route and reject anonymous requests with 401.\n` +
          `2. Return only the fields the caller is allowed to see, and only their own records.\n` +
          `3. If the endpoint is meant to be public, make sure it never includes personal fields such as email, phone or user IDs.\n` +
          `Then run: npx vibeprobe ${surface.origin} --recheck SEC-03`,
      });
    }
    return findings;
  },
};
