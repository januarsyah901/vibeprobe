import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { GuardedHttpClient, Scope, crawl, runChecks, type RunResult } from '@vibeprobe/core';
import { createApp as vulnerableApp } from '../../../fixtures/vulnerable-app/server';
import { createApp as safeApp } from '../../../fixtures/safe-app/server';
import { allChecks } from '../src';

async function scan(server: Server): Promise<{ result: RunResult; base: string }> {
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const client = new GuardedHttpClient({ scope: new Scope(), requestsPerSecond: 1000, sleep: async () => {} });
  try {
    const target = new URL(base);
    const surface = await crawl(client, target);
    return { result: await runChecks(allChecks, { client, surface, target }), base };
  } finally {
    await client.close();
  }
}

const listen = (s: Server) => new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
const close = (s: Server) => new Promise<void>((r) => s.close(() => r()));

describe('vulnerable-app: every planted hole is found', () => {
  const server = vulnerableApp();
  let out: Awaited<ReturnType<typeof scan>>;
  beforeAll(async () => {
    await listen(server);
    out = await scan(server);
  });
  afterAll(() => close(server));

  it('runs every check without errors', () => expect(out.result.errors).toEqual([]));

  it.each([
    ['SEC-01', 'Stripe secret key'],
    ['SEC-01', 'AWS access key ID'],
    ['SEC-01', 'Supabase service_role key'],
    ['SEC-06', '.env'],
    ['SEC-06', '.git/HEAD'],
    ['SEC-06', '.git/config'],
    ['SEC-08', 'Any website can read'],
    ['SEC-09', 'security header'],
    ['SEC-11', 'source code can be downloaded'],
  ])('%s: %s', (id, text) => {
    expect(out.result.findings.some((f) => f.checkId === id && f.title.includes(text))).toBe(true);
  });

  it('sorts the worst first', () => expect(out.result.findings[0]!.severity).toBe('critical'));

  it('never prints a full secret in a report', () => {
    const json = JSON.stringify(out.result.findings);
    expect(json).not.toContain('sk_' + 'live_' + 'A1b2C3d4E5f6G7h8I9j0K1l2');
    expect(json).not.toContain('IOSFODNN7EXAMPLE');
    expect(json).not.toContain('hunter2');
    expect(json).not.toContain('token123@');
  });

  it('gives every finding a fix prompt and a read-only curl', () => {
    for (const f of out.result.findings) {
      expect(f.fixPrompt.length).toBeGreaterThan(40);
      expect(f.reproduce).toMatch(/^curl /);
    }
  });
});

describe('safe-app: zero findings', () => {
  const server = safeApp();
  let out: Awaited<ReturnType<typeof scan>>;
  beforeAll(async () => {
    await listen(server);
    out = await scan(server);
  });
  afterAll(() => close(server));

  it('runs every check without errors', () => expect(out.result.errors).toEqual([]));
  it('reports nothing (public anon key and SPA-style 200s are not leaks)', () => {
    expect(out.result.findings).toEqual([]);
  });
});
