import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createApp as vulnerableApp } from '../../../fixtures/vulnerable-app/server';
import { createApp as safeApp } from '../../../fixtures/safe-app/server';
import { main, normalizeArgv } from '../src/index';

const listen = (s: Server) => new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
const close = (s: Server) => new Promise<void>((r) => s.close(() => r()));
const url = (s: Server) => `http://127.0.0.1:${(s.address() as AddressInfo).port}`;

const vulnerable = vulnerableApp();
const safe = safeApp();
const methods: string[] = [];
// A target that only counts what it receives, to prove --plan sends no write request.
const counter = createServer((req, res) => {
  methods.push(req.method!);
  res.writeHead(200, { 'content-type': 'text/html' }).end('<!doctype html><title>x</title><script src="/a.js"></script>');
});

let dir: string;
let out: string[];

beforeAll(async () => {
  await Promise.all([listen(vulnerable), listen(safe), listen(counter)]);
});
afterAll(async () => {
  await Promise.all([close(vulnerable), close(safe), close(counter)]);
});
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'vibeprobe-active-'));
  out = [];
  methods.length = 0;
  vi.spyOn(console, 'log').mockImplementation((...a) => void out.push(a.join(' ')));
  vi.spyOn(console, 'error').mockImplementation((...a) => void out.push(a.join(' ')));
});
afterEach(async () => {
  vi.restoreAllMocks();
  await rm(dir, { recursive: true, force: true });
});

const run = (target: string, ...args: string[]) => main([target, '--out', join(dir, 'report'), '--rate', '500', ...args]);
const text = () => out.join('\n');

describe('normalizeArgv', () => {
  it.each([
    [['--active', 'http://localhost:3000'], ['--active=light', 'http://localhost:3000']],
    [['http://localhost:3000', '--active'], ['http://localhost:3000', '--active=light']],
    [['--active', 'full', 'http://localhost:3000'], ['--active=full', 'http://localhost:3000']],
    [['--active=full', 'http://localhost:3000'], ['--active=full', 'http://localhost:3000']],
    [['http://localhost:3000'], ['http://localhost:3000']],
  ])('%j', (input, expected) => expect(normalizeArgv(input)).toEqual(expected));
});

describe('--active', () => {
  it('finds the planted holes on the vulnerable app and fails', async () => {
    expect(await run(url(vulnerable), '--active', 'full', '--yes')).toBe(1);
    expect(text()).toContain('Active mode (full)');
    expect(text()).toMatch(/\[CRITICAL\].*\(ACT-0[2489]/);
    const report = JSON.parse(await readFile(join(dir, 'report', 'report.json'), 'utf8'));
    expect(report.mode).toBe('active-full');
    expect(new Set(report.findings.map((f: { checkId: string }) => f.checkId.slice(0, 3)))).toEqual(new Set(['SEC', 'ACT']));
    expect(report.requests.length).toBeGreaterThan(40);
    expect(report.requests.some((r: { method: string }) => r.method === 'DELETE')).toBe(false);
  });

  it('writes the audit table into the markdown and html reports', async () => {
    await run(url(vulnerable), '--active', '--yes');
    expect(await readFile(join(dir, 'report', 'report.md'), 'utf8')).toContain('What vibeprobe sent (active mode)');
    expect(await readFile(join(dir, 'report', 'report.html'), 'utf8')).toContain('What vibeprobe sent');
  });

  it('passes on the safe app, even in full mode', async () => {
    expect(await run(url(safe), '--active=full', '--yes')).toBe(0);
    expect(text()).toContain('No findings');
  });

  it('light is the default and skips the heavy checks', async () => {
    await run(url(vulnerable), '--active', '--yes');
    expect(text()).toContain('Active mode (light)');
    expect(text()).not.toContain('ACT-05');
    expect(text()).not.toContain('ACT-13');
  });

  it('refuses to run without confirmation when there is no terminal (CI needs --yes)', async () => {
    expect(await run(url(safe), '--active')).toBe(2);
    expect(text()).toContain('needs your confirmation');
    expect(text()).toContain('--yes');
  });

  it('refuses a target that is not localhost, before any request', async () => {
    expect(await main(['https://example.com', '--active', '--yes'])).toBe(2);
    expect(text()).toContain('only runs against localhost');
  });

  it('rejects a bad intensity', async () => {
    expect(await run(url(safe), '--active=max', '--yes')).toBe(2);
    expect(text()).toContain('Invalid --active');
  });
});

describe('--plan', () => {
  it('lists the requests and sends no write request', async () => {
    expect(await run(url(vulnerable), '--active', 'full', '--plan')).toBe(0);
    expect(text()).toMatch(/Plan: \d+ requests would be sent\. None were\./);
    expect(text()).toMatch(/ACT-06\s+POST\s+http/);
    expect(text()).not.toContain('Check ACT');
  });

  it('never sends POST, PUT or PATCH to the target', async () => {
    await run(url(counter), '--active', 'full', '--plan');
    expect(methods.filter((m) => !['GET', 'HEAD', 'OPTIONS'].includes(m))).toEqual([]);
  });

  it('needs --active', async () => {
    expect(await run(url(safe), '--plan')).toBe(2);
    expect(text()).toContain('--plan needs --active');
  });
});

describe('--recheck with active checks', () => {
  it('asks for --active', async () => {
    expect(await run(url(safe), '--recheck', 'ACT-01')).toBe(2);
    expect(text()).toContain('is an active check');
  });

  it('says still broken on the vulnerable app and looks fixed on the safe app', async () => {
    expect(await run(url(vulnerable), '--active', '--yes', '--recheck', 'ACT-01')).toBe(1);
    expect(text()).toContain('still');
    out.length = 0;
    expect(await run(url(safe), '--active', '--yes', '--recheck', 'ACT-01')).toBe(0);
    expect(text()).toContain('Looks fixed');
  });
});

describe('--sarif', () => {
  it('writes a SARIF 2.1.0 file for GitHub code scanning', async () => {
    const file = join(dir, 'out', 'vibeprobe.sarif');
    await run(url(vulnerable), '--sarif', file);
    const sarif = JSON.parse(await readFile(file, 'utf8'));
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0].tool.driver.name).toBe('vibeprobe');
    expect(sarif.runs[0].results.length).toBeGreaterThan(10);
    expect(JSON.stringify(sarif)).not.toContain('sk_' + 'live_');
  });
});
