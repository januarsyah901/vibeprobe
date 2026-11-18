import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

export interface CanaryHit {
  token: string;
  path: string;
  at: number;
}

/**
 * A tiny listener on 127.0.0.1 used to prove SSRF without harm: vibeprobe gives the app a URL that
 * points here. If the app's *server* fetches it, the hit lands here. It only listens, never sends.
 */
export interface Canary {
  urlFor(token: string): string;
  hits(token?: string): CanaryHit[];
  close(): Promise<void>;
}

export async function startCanary(): Promise<Canary> {
  const hits: CanaryHit[] = [];
  const server: Server = createServer((req, res) => {
    const path = req.url ?? '/';
    const token = path.split('/').filter(Boolean).pop() ?? '';
    hits.push({ token, path, at: Date.now() });
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('vibeprobe canary');
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = (server.address() as AddressInfo).port;
  return {
    urlFor: (token) => `http://127.0.0.1:${port}/vp-ssrf/${token}`,
    hits: (token) => (token === undefined ? [...hits] : hits.filter((h) => h.token === token)),
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
