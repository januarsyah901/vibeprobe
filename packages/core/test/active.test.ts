import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  ActiveModeError,
  GuardedHttpClient,
  MethodNotAllowedError,
  RequestBudgetError,
  Scope,
  ScopeError,
  createActiveClient,
  extractForms,
  extractParams,
  extractWriteEndpoints,
  grantActiveConsent,
  runChecks,
  startCanary,
  type Check,
  type SurfaceMap,
} from '../src';

let server: Server;
let base: string;
let hits: { method: string; url: string; body: string }[] = [];
let busyCount = 0;

beforeAll(async () => {
  server = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      hits.push({ method: req.method!, url: req.url!, body });
      if (req.url === '/redirect') return res.writeHead(302, { location: '/ok' }).end();
      if (req.url === '/busy') {
        busyCount++;
        return res.writeHead(503).end('busy');
      }
      res.writeHead(200, { 'content-type': 'text/plain' }).end('ok');
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => new Promise<void>((r) => server.close(() => r())));
beforeEach(() => {
  hits = [];
  busyCount = 0;
});

const target = () => new URL(base);
const consent = () => grantActiveConsent({ target: target(), acknowledged: true });
const opts = () => ({ scope: new Scope(), requestsPerSecond: 5000, sleep: async () => {} });

describe('active-mode consent', () => {
  it('is refused without an explicit yes', () => {
    expect(() => grantActiveConsent({ target: target(), acknowledged: false })).toThrow(ActiveModeError);
  });

  it.each(['https://example.com', 'http://192.168.1.10', 'http://10.0.0.5:3000'])('is refused for a target that is not localhost (%s)', (url) => {
    expect(() => grantActiveConsent({ target: new URL(url), acknowledged: true })).toThrow(/only runs against localhost/);
  });

  it.each(['http://localhost:3000', 'http://127.0.0.1:8080', 'http://[::1]:3000', 'http://app.localhost:3000'])('is granted for %s', (url) => {
    expect(grantActiveConsent({ target: new URL(url), acknowledged: true }).host).toBeTruthy();
  });

  it('cannot be forged with new', () => {
    // @ts-expect-error the constructor needs a private key
    expect(() => new (grantActiveConsent({ target: target(), acknowledged: true }).constructor)('localhost', Symbol('x'))).toThrow(ActiveModeError);
  });
});

describe('write methods need consent', () => {
  it.each(['POST', 'PUT', 'PATCH'] as const)('a plain client cannot even be built to allow %s', (method) => {
    expect(() => new GuardedHttpClient({ ...opts(), allowedMethods: ['GET', method] })).toThrow(ActiveModeError);
  });

  it('refuses a fake consent object', () => {
    expect(() => new GuardedHttpClient({ ...opts(), allowedMethods: ['GET', 'POST'], activeConsent: {} as never })).toThrow(ActiveModeError);
  });

  it('never allows DELETE, even with consent', () => {
    expect(() => new GuardedHttpClient({ ...opts(), allowedMethods: ['GET', 'DELETE'], activeConsent: consent() })).toThrow(/never sends DELETE/);
    const c = createActiveClient({ ...opts(), consent: consent() });
    return expect(c.request(base, { method: 'DELETE' })).rejects.toThrow(MethodNotAllowedError).finally(() => c.close());
  });

  it('the default client still refuses POST and sends nothing', async () => {
    const c = new GuardedHttpClient(opts());
    await expect(c.request(base, { method: 'POST', body: 'x' })).rejects.toThrow(MethodNotAllowedError);
    expect(hits).toEqual([]);
    await c.close();
  });
});

describe('active client', () => {
  it('sends a POST body, and still sends GET', async () => {
    const c = createActiveClient({ ...opts(), consent: consent() });
    expect((await c.request(`${base}/x`, { method: 'POST', body: '{"a":1}', headers: { 'content-type': 'application/json' } })).status).toBe(200);
    await c.request(`${base}/y`);
    expect(hits).toEqual([
      { method: 'POST', url: '/x', body: '{"a":1}' },
      { method: 'GET', url: '/y', body: '' },
    ]);
    await c.close();
  });

  it('does not send a body with GET', async () => {
    const c = createActiveClient({ ...opts(), consent: consent() });
    await c.request(`${base}/g`, { body: 'sneaky' });
    expect(hits[0]!.body).toBe('');
    await c.close();
  });

  it('refuses a write to anything but localhost, even if the scope allows the host', async () => {
    const scope = new Scope({ verifiedHosts: ['example.com'] });
    const c = createActiveClient({ ...opts(), scope, consent: consent() });
    await expect(c.request('https://example.com/x', { method: 'POST', body: '{}' })).rejects.toThrow(/only sent to localhost/);
    await c.close();
  });

  it('does not follow a redirect after a write', async () => {
    const c = createActiveClient({ ...opts(), consent: consent() });
    const res = await c.request(`${base}/redirect`, { method: 'POST', body: '{}' });
    expect(res.status).toBe(302);
    expect(hits.map((h) => h.url)).toEqual(['/redirect']);
    await c.close();
  });

  it('can skip redirects on GET too, which lets a check read the Location header', async () => {
    const c = new GuardedHttpClient(opts());
    const res = await c.request(`${base}/redirect`, { followRedirects: false });
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/ok');
    await c.close();
  });

  it('never retries a write, but still retries a GET', async () => {
    const c = createActiveClient({ ...opts(), consent: consent() });
    await c.request(`${base}/busy`, { method: 'POST', body: '{}' });
    expect(busyCount).toBe(1);
    busyCount = 0;
    await c.request(`${base}/busy`);
    expect(busyCount).toBe(3);
    await c.close();
  });

  it('stops at the request budget', async () => {
    const c = createActiveClient({ ...opts(), consent: consent(), maxRequests: 3 });
    for (let i = 0; i < 3; i++) await c.request(`${base}/b`);
    await expect(c.request(`${base}/b`)).rejects.toThrow(RequestBudgetError);
    expect(hits).toHaveLength(3);
    await c.close();
  });

  it('records every request in the audit trail', async () => {
    const c = createActiveClient({ ...opts(), consent: consent() });
    await c.request(`${base}/a`, { tag: 'ACT-01' });
    await c.request(`${base}/b`, { method: 'PUT', body: '{"k":1}', tag: 'ACT-07' });
    expect(c.history).toEqual([
      { tag: 'ACT-01', method: 'GET', url: `${base}/a`, status: 200, body: undefined },
      { tag: 'ACT-07', method: 'PUT', url: `${base}/b`, status: 200, body: '{"k":1}' },
    ]);
    await c.close();
  });
});

describe('--plan (dry run)', () => {
  it('records requests and sends none', async () => {
    const c = createActiveClient({ ...opts(), consent: consent(), dryRun: true });
    const res = await c.request(`${base}/p`, { method: 'POST', body: '{"x":1}', tag: 'ACT-06' });
    await c.request(`${base}/q`);
    expect(hits).toEqual([]);
    expect(res.status).toBe(0);
    expect(c.history.map((h) => [h.method, h.planned])).toEqual([['POST', true], ['GET', true]]);
    await c.close();
  });

  it('still refuses out-of-scope targets in the plan', async () => {
    const c = createActiveClient({ ...opts(), consent: consent(), dryRun: true });
    await expect(c.request('http://example.com/', { method: 'POST' })).rejects.toThrow(ScopeError);
    await c.close();
  });
});

describe('the runner labels requests with the check id', () => {
  it('tags each request with the check that sent it', async () => {
    const c = createActiveClient({ ...opts(), consent: consent() });
    const one: Check = { id: 'ACT-01', title: 't', severity: 'low', mode: 'active', run: async ({ client }) => (await client.request(`${base}/one`), []) };
    const two: Check = { id: 'ACT-02', title: 't', severity: 'low', mode: 'active', run: async ({ client }) => (await client.request(`${base}/two`), []) };
    await runChecks([one, two], { client: c, surface: {} as SurfaceMap, target: target() }, { concurrency: 1 });
    expect(c.history.map((h) => [h.tag, new URL(h.url).pathname])).toEqual([['ACT-01', '/one'], ['ACT-02', '/two']]);
    await c.close();
  });
});

describe('canary', () => {
  it('records a hit from a server-side fetch and nothing else', async () => {
    const canary = await startCanary();
    const url = canary.urlFor('vptoken');
    expect(url).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/vp-ssrf\/vptoken$/);
    expect(canary.hits()).toEqual([]);
    await fetch(url); // stands in for the app's server
    expect(canary.hits('vptoken')).toHaveLength(1);
    expect(canary.hits('other')).toHaveLength(0);
    await canary.close();
  });
});

describe('crawler extraction', () => {
  it('reads forms, with their method and fields', () => {
    const html = '<form action="/search"><input name="q"></form><form method="POST" action="/api/x"><input name="a"><textarea name="b"></textarea></form><form action="https://other.example/x"><input name="z"></form>';
    expect(extractForms(html, new URL('http://localhost:3000/'))).toEqual([
      { action: 'http://localhost:3000/search', method: 'GET', fields: ['q'], page: 'http://localhost:3000/' },
      { action: 'http://localhost:3000/api/x', method: 'POST', fields: ['a', 'b'], page: 'http://localhost:3000/' },
    ]);
  });

  it('reads query parameters from JavaScript strings', () => {
    const params = extractParams('const a = "/search?q="; fetch(`/api/items?id=${id}&sort=asc`);', 'http://localhost:3000');
    expect(params.map((p) => `${new URL(p.url).pathname}?${p.name}`).sort()).toEqual(['/api/items?id', '/api/items?sort', '/search?q']);
  });

  it('reads endpoints called with POST, PUT or PATCH', () => {
    const js = 'fetch("/api/a", { method: "POST", body: x }); axios.put("/api/b", d); fetch("/api/c"); fetch("/api/d", { method: "PATCH" });';
    expect(extractWriteEndpoints(js, 'http://localhost:3000').map((w) => `${w.method} ${new URL(w.url).pathname}`).sort()).toEqual(['PATCH /api/d', 'POST /api/a', 'PUT /api/b']);
  });
});
