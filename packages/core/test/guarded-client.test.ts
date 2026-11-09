import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  GuardedHttpClient,
  MethodNotAllowedError,
  Scope,
  ScopeError,
  TooManyRedirectsError,
  type GuardedHttpClientOptions,
  type Resolver,
} from '../src';

type Handler = (req: IncomingMessage, res: ServerResponse) => void;

let server: Server;
let base: string;
let port: number;
let hits: { method: string; url: string }[] = [];
const routes = new Map<string, Handler>();

beforeAll(async () => {
  server = createServer((req, res) => {
    hits.push({ method: req.method!, url: req.url! });
    const handler = routes.get(req.url!.split('?')[0]!);
    if (handler) return handler(req, res);
    res.writeHead(404).end('not found');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  port = (server.address() as AddressInfo).port;
  base = `http://127.0.0.1:${port}`;

  routes.set('/ok', (_req, res) => res.writeHead(200, { 'content-type': 'text/plain' }).end('hello'));
  routes.set('/to-ok', (_req, res) => res.writeHead(302, { location: '/ok' }).end());
  routes.set('/to-outside', (_req, res) =>
    res.writeHead(302, { location: 'http://example.com/steal' }).end(),
  );
  routes.set('/to-metadata', (_req, res) =>
    res.writeHead(301, { location: 'http://169.254.169.254/latest/meta-data/' }).end(),
  );
  routes.set('/loop', (_req, res) => res.writeHead(302, { location: '/loop' }).end());
  routes.set('/big', (_req, res) => res.writeHead(200).end('x'.repeat(10_000)));
});

afterAll(() => new Promise<void>((r) => server.close(() => r())));

beforeEach(() => {
  hits = [];
});

function client(opts: Partial<GuardedHttpClientOptions> = {}) {
  return new GuardedHttpClient({
    scope: new Scope(),
    requestsPerSecond: 1000,
    sleep: async () => {},
    ...opts,
  });
}

describe('GuardedHttpClient', () => {
  it('sends GET to a local target', async () => {
    const c = client();
    const res = await c.request(`${base}/ok`);
    expect(res.status).toBe(200);
    expect(res.body).toBe('hello');
    expect(res.redirects).toEqual([]);
    await c.close();
  });

  it.each(['POST', 'PUT', 'PATCH', 'DELETE'] as const)('refuses %s by default without sending it', async (method) => {
    const c = client();
    await expect(c.request(`${base}/ok`, { method })).rejects.toThrow(MethodNotAllowedError);
    expect(hits).toEqual([]);
    await c.close();
  });

  it('refuses an out-of-scope target without sending anything', async () => {
    const c = client();
    await expect(c.request('http://example.com/')).rejects.toThrow(ScopeError);
    await c.close();
  });

  it('follows a redirect that stays in scope', async () => {
    const c = client();
    const res = await c.request(`${base}/to-ok`);
    expect(res.status).toBe(200);
    expect(res.url).toBe(`${base}/ok`);
    expect(res.redirects).toEqual([`${base}/to-ok`]);
    await c.close();
  });

  it.each(['/to-outside', '/to-metadata'])('refuses a redirect out of scope (%s)', async (path) => {
    const c = client();
    await expect(c.request(`${base}${path}`)).rejects.toThrow(ScopeError);
    expect(hits).toEqual([{ method: 'GET', url: path }]);
    await c.close();
  });

  it('stops redirect loops', async () => {
    const c = client({ maxRedirects: 3 });
    await expect(c.request(`${base}/loop`)).rejects.toThrow(TooManyRedirectsError);
    expect(hits).toHaveLength(4);
    await c.close();
  });

  it('connects when a local name resolves to loopback', async () => {
    const resolver: Resolver = async () => [{ address: '127.0.0.1', family: 4 }];
    const c = client({ resolver });
    const res = await c.request(`http://app.localhost:${port}/ok`);
    expect(res.status).toBe(200);
    await c.close();
  });

  it('refuses a local name that resolves off loopback (DNS rebinding)', async () => {
    const resolver: Resolver = async () => [{ address: '93.184.216.34', family: 4 }];
    const c = client({ resolver });
    await expect(c.request(`http://app.localhost:${port}/ok`)).rejects.toThrow(ScopeError);
    expect(hits).toEqual([]);
    await c.close();
  });

  it('refuses when any resolved address is forbidden', async () => {
    const resolver: Resolver = async () => [
      { address: '127.0.0.1', family: 4 },
      { address: '10.0.0.7', family: 4 },
    ];
    const c = client({ resolver });
    await expect(c.request(`http://app.localhost:${port}/ok`)).rejects.toThrow(ScopeError);
    expect(hits).toEqual([]);
    await c.close();
  });

  it('refuses a verified public name that resolves to an internal address', async () => {
    const resolver: Resolver = async () => [{ address: '192.168.1.10', family: 4 }];
    const c = client({ scope: new Scope({ verifiedHosts: ['myapp.example'] }), resolver });
    await expect(c.request('http://myapp.example/')).rejects.toThrow(ScopeError);
    await c.close();
  });

  it('retries after 429 and honours Retry-After', async () => {
    let calls = 0;
    routes.set('/busy', (_req, res) => {
      calls++;
      if (calls === 1) return res.writeHead(429, { 'retry-after': '3' }).end();
      res.writeHead(200).end('done');
    });
    const delays: number[] = [];
    const c = client({ sleep: async (ms) => void delays.push(ms) });
    const res = await c.request(`${base}/busy`);
    expect(res.status).toBe(200);
    expect(calls).toBe(2);
    expect(delays).toContain(3000);
    await c.close();
  });

  it('gives up after maxRetries and returns the last response', async () => {
    routes.set('/down', (_req, res) => res.writeHead(503).end());
    const c = client({ maxRetries: 2 });
    const res = await c.request(`${base}/down`);
    expect(res.status).toBe(503);
    expect(hits).toHaveLength(3);
    await c.close();
  });

  it('caps response bodies', async () => {
    const c = client({ maxBodyBytes: 100 });
    const res = await c.request(`${base}/big`);
    expect(res.body).toHaveLength(100);
    expect(res.truncated).toBe(true);
    await c.close();
  });

  it('rate-limits requests', async () => {
    const c = new GuardedHttpClient({ scope: new Scope(), requestsPerSecond: 20 });
    const start = Date.now();
    for (let i = 0; i < 5; i++) await c.request(`${base}/ok`);
    // burst 1 at 20 rps: 4 waits of ~50 ms
    expect(Date.now() - start).toBeGreaterThanOrEqual(180);
    await c.close();
  });
});
