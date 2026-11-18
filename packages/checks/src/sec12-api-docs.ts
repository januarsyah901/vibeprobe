import { curlFor, type Check, type Finding } from '@vibeprobe/core';

const DOC_PATHS = ['/openapi.json', '/swagger.json', '/v3/api-docs', '/api-docs', '/api/openapi.json', '/swagger/v1/swagger.json'];
const UI_PATHS = ['/docs', '/swagger-ui/', '/redoc'];
const GRAPHQL_PATHS = ['/graphql', '/api/graphql'];
const INTROSPECTION = '{__schema{types{name}}}';

const isJson = (type: string | null) => (type ?? '').includes('json');

export const sec12: Check = {
  id: 'SEC-12',
  title: 'API documentation or GraphQL schema is public',
  severity: 'medium',
  async run({ client, surface }) {
    const findings: Finding[] = [];
    const found = (title: string, url: string, status: number, excerpt: string, what: string) =>
      findings.push({
        checkId: 'SEC-12',
        title,
        severity: 'medium',
        confidence: 'medium',
        url,
        why: 'Anyone can read a complete map of your API: every route, parameter and data shape. That saves an attacker hours of guessing. If this API is public on purpose, ignore this.',
        evidence: { request: `GET ${url}`, status, excerpt },
        reproduce: curlFor(url),
        fixPrompt:
          `${what} is reachable by anyone without logging in. Please:\n` +
          `1. Disable it in production, or put it behind authentication. For GraphQL that means turning introspection off when NODE_ENV is "production".\n` +
          `2. Do not rely on hiding the docs: every endpoint it lists must still check who is asking.\n` +
          `Then run: npx vibeprobe ${surface.origin} --recheck SEC-12`,
      });

    for (const path of DOC_PATHS) {
      const url = new URL(path, surface.origin).href;
      const res = await client.request(url);
      if (res.status !== 200 || !isJson(res.headers.get('content-type'))) continue;
      try {
        const doc = JSON.parse(res.body) as { openapi?: unknown; swagger?: unknown; paths?: object };
        if ((doc.openapi || doc.swagger) && doc.paths) {
          found(`API documentation is public (${path})`, url, 200, `OpenAPI document listing ${Object.keys(doc.paths).length} route(s)`, `The OpenAPI file ${path}`);
        }
      } catch {
        /* not JSON after all */
      }
    }
    for (const path of UI_PATHS) {
      const url = new URL(path, surface.origin).href;
      const res = await client.request(url);
      if (res.status === 200 && /swagger-ui|redoc|Swagger UI/i.test(res.body) && /<title>[^<]*(swagger|redoc|api)/i.test(res.body)) {
        found(`API documentation page is public (${path})`, url, 200, 'interactive API documentation page', `The API documentation page ${path}`);
      }
    }
    for (const path of GRAPHQL_PATHS) {
      const url = new URL(`${path}?query=${encodeURIComponent(INTROSPECTION)}`, surface.origin).href;
      const res = await client.request(url);
      if (res.status !== 200 || !isJson(res.headers.get('content-type'))) continue;
      try {
        const data = JSON.parse(res.body) as { data?: { __schema?: { types?: unknown[] } } };
        const types = data.data?.__schema?.types;
        if (Array.isArray(types)) {
          found(`GraphQL introspection is enabled (${path})`, url, 200, `schema lists ${types.length} type(s)`, `GraphQL introspection on ${path}`);
        }
      } catch {
        /* not GraphQL */
      }
    }
    return findings;
  },
};
