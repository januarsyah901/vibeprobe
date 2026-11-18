import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  GuardedHttpClient,
  Scope,
  crawl,
  createActiveClient,
  grantActiveConsent,
  runChecks,
  startCanary,
  type RunResult,
  type RequestRecord,
} from '@vibeprobe/core';
import { createApp as vulnerableApp } from '../../../fixtures/vulnerable-app/server';
import { createApp as safeApp } from '../../../fixtures/safe-app/server';
import { activeChecks, activeChecksFor, allChecks } from '../src';

async function scanActive(server: Server, intensity: 'light' | 'full' = 'full'): Promise<{ result: RunResult; history: RequestRecord[] }> {
  const target = new URL(`http://127.0.0.1:${(server.address() as AddressInfo).port}`);
  const opts = { scope: new Scope(), requestsPerSecond: 5000, sleep: async () => {} };
  const passive = new GuardedHttpClient(opts);
  const active = createActiveClient({ ...opts, consent: grantActiveConsent({ target, acknowledged: true }) });
  const canary = await startCanary();
  try {
    const surface = await crawl(passive, target);
    const result = await runChecks(activeChecksFor(intensity), { client: active, surface, target, canary });
    return { result, history: active.history };
  } finally {
    await canary.close();
    await Promise.all([passive.close(), active.close()]);
  }
}

const listen = (s: Server) => new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
const close = (s: Server) => new Promise<void>((r) => s.close(() => r()));

describe('active checks on vulnerable-app: every planted hole is found', () => {
  const server = vulnerableApp();
  let out: Awaited<ReturnType<typeof scanActive>>;
  beforeAll(async () => {
    await listen(server);
    out = await scanActive(server);
  });
  afterAll(() => close(server));

  it('runs every check without errors', () => expect(out.result.errors).toEqual([]));

  it.each([
    ['ACT-01', '"q" input on /search'],
    ['ACT-02', '"id" input on /api/items'],
    ['ACT-03', '/api/settings accepts a form post'],
    ['ACT-04', '"file" input on /download'],
    ['ACT-05', '/api/login lets anyone try wrong passwords'],
    ['ACT-06', '/api/items accepts POST'],
    ['ACT-07', '/api/profile accepts fields'],
    ['ACT-08', '/api/login can be logged into'],
    ['ACT-09', '"name" input on /greet'],
    ['ACT-10', '"url" input on /api/fetch'],
    ['ACT-11', '/reset builds links'],
    ['ACT-12', '/api/v1/admin exists'],
    ['ACT-13', '/api/merge lets a request change every object'],
  ])('%s: %s', (id, text) => {
    expect(out.result.findings.some((f) => f.checkId === id && f.title.includes(text))).toBe(true);
  });

  it('gives every finding evidence, a curl and a fix prompt', () => {
    for (const f of out.result.findings) {
      expect(f.checkId).toMatch(/^ACT-\d{2}$/);
      expect(f.fixPrompt).toContain('--recheck ' + f.checkId);
      expect(f.reproduce).toMatch(/^curl /);
      expect(f.evidence.request.length).toBeGreaterThan(5);
    }
  });

  it('never sends DELETE, and every request is in the audit trail', () => {
    expect(out.history.length).toBeGreaterThan(40);
    expect(out.history.some((r) => r.method === 'DELETE')).toBe(false);
    expect(out.history.every((r) => r.tag?.startsWith('ACT-'))).toBe(true);
    expect(new Set(out.history.map((r) => r.method))).toEqual(new Set(['GET', 'POST', 'PUT']));
  });

  it('does not touch the real Object.prototype (prototype pollution runs on a sandbox)', () => {
    expect(({} as Record<string, unknown>).vpPolluted).toBeUndefined();
  });
});

describe('active checks on safe-app: zero findings', () => {
  const server = safeApp();
  let out: Awaited<ReturnType<typeof scanActive>>;
  beforeAll(async () => {
    await listen(server);
    out = await scanActive(server);
  });
  afterAll(() => close(server));

  it('runs every check without errors', () => expect(out.result.errors).toEqual([]));
  it('reports nothing', () => expect(out.result.findings).toEqual([]));
  it('did send write requests, so the silence is meaningful', () => {
    expect(out.history.filter((r) => r.method === 'POST').length).toBeGreaterThan(10);
  });
});

describe('profiles', () => {
  it('light is a strict subset of full', () => {
    const light = activeChecksFor('light').map((c) => c.id);
    expect(light).toEqual(['ACT-01', 'ACT-02', 'ACT-03', 'ACT-04', 'ACT-11', 'ACT-12']);
    expect(activeChecksFor('full')).toHaveLength(activeChecks.length);
  });

  it('every active check is marked active and passive checks are not', () => {
    expect(activeChecks.every((c) => c.mode === 'active')).toBe(true);
    expect(allChecks.every((c) => (c.mode ?? 'passive') === 'passive')).toBe(true);
  });

  it('light does not run the heavier probes against the vulnerable app', async () => {
    const server = vulnerableApp();
    await listen(server);
    try {
      const { result, history } = await scanActive(server, 'light');
      expect(new Set(result.findings.map((f) => f.checkId))).toEqual(new Set(['ACT-01', 'ACT-02', 'ACT-03', 'ACT-04', 'ACT-11', 'ACT-12']));
      const ran = new Set(history.map((r) => r.tag));
      for (const heavy of ['ACT-05', 'ACT-06', 'ACT-07', 'ACT-08', 'ACT-09', 'ACT-10', 'ACT-13']) expect(ran.has(heavy)).toBe(false);
    } finally {
      await close(server);
    }
  });
});
