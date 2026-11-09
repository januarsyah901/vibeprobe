import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Finding } from '@vibeprobe/core';
import { createApp as vulnerableApp } from '../../../fixtures/vulnerable-app/server';
import { createApp as safeApp } from '../../../fixtures/safe-app/server';
import { fingerprint, isFailLevel, meetsFailLevel } from '../src/baseline';
import { main } from '../src/index';

const listen = (s: Server) => new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
const close = (s: Server) => new Promise<void>((r) => s.close(() => r()));
const url = (s: Server) => `http://127.0.0.1:${(s.address() as AddressInfo).port}`;

const vulnerable = vulnerableApp();
const safe = safeApp();
let dir: string;
let out: string[];

beforeAll(async () => {
  await Promise.all([listen(vulnerable), listen(safe)]);
});
afterAll(async () => {
  await Promise.all([close(vulnerable), close(safe)]);
});
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'vibeprobe-test-'));
  out = [];
  vi.spyOn(console, 'log').mockImplementation((...a) => void out.push(a.join(' ')));
  vi.spyOn(console, 'error').mockImplementation((...a) => void out.push(a.join(' ')));
});
afterEach(async () => {
  vi.restoreAllMocks();
  await rm(dir, { recursive: true, force: true });
});

const scan = (target: Server, ...args: string[]) => main([url(target), '--out', join(dir, 'report'), '--rate', '500', ...args]);
const text = () => out.join('\n');

describe('--fail-on', () => {
  it('fails by default when there are findings', async () => {
    expect(await scan(vulnerable)).toBe(1);
  });

  it('exits 0 for --fail-on none even with findings', async () => {
    expect(await scan(vulnerable, '--fail-on', 'none')).toBe(0);
    expect(text()).toContain('findings:');
  });

  it('only fails at or above the level', async () => {
    // The vulnerable app has critical findings, so every level up to critical fails.
    expect(await scan(vulnerable, '--fail-on', 'critical')).toBe(1);
    // The safe app has none at all.
    expect(await scan(safe, '--fail-on', 'low')).toBe(0);
  });

  it('rejects a bad --rate with exit 2', async () => {
    expect(await scan(safe, '--rate', '0')).toBe(2);
    expect(text()).toContain('Invalid --rate');
  });

  it('rejects an unknown level with exit 2', async () => {
    expect(await scan(safe, '--fail-on', 'banana')).toBe(2);
    expect(text()).toContain('Invalid --fail-on "banana"');
  });
});

describe('baseline', () => {
  it('--write-baseline saves findings and exits 0', async () => {
    const file = join(dir, 'baseline.json');
    expect(await scan(vulnerable, '--write-baseline', file)).toBe(0);
    const saved = JSON.parse(await readFile(file, 'utf8'));
    expect(saved.version).toBe(1);
    expect(saved.findings.length).toBeGreaterThan(5);
    expect(JSON.stringify(saved)).not.toContain('sk_' + 'live_');
  });

  it('a second scan with the baseline reports nothing new and passes', async () => {
    const file = join(dir, 'baseline.json');
    await scan(vulnerable, '--write-baseline', file);
    out.length = 0;
    expect(await scan(vulnerable, '--baseline', file)).toBe(0);
    expect(text()).toContain('accepted by baseline');
    expect(text()).not.toContain('[CRITICAL]');
    const report = JSON.parse(await readFile(join(dir, 'report', 'report.json'), 'utf8'));
    expect(report.findings.filter((f: Finding) => f.confidence !== 'low')).toEqual([]);
  });

  it('still fails on a finding that is not in the baseline', async () => {
    const file = join(dir, 'baseline.json');
    const saved = { version: 1, findings: [] as unknown[] };
    // Baseline from the safe app (empty) applied to the vulnerable app: everything is new.
    await writeFile(file, JSON.stringify(saved));
    expect(await scan(vulnerable, '--baseline', file)).toBe(1);
  });

  it('exits 2 when the baseline file is missing or invalid', async () => {
    expect(await scan(safe, '--baseline', join(dir, 'nope.json'))).toBe(2);
    expect(text()).toContain('Baseline file not found');
    const bad = join(dir, 'bad.json');
    await writeFile(bad, '{"hello":1}');
    out.length = 0;
    expect(await scan(safe, '--baseline', bad)).toBe(2);
    expect(text()).toContain('not a valid vibeprobe baseline');
  });
});

describe('fingerprint and helpers', () => {
  const f: Finding = {
    checkId: 'SEC-09',
    title: '4 browser security headers are missing',
    severity: 'low',
    confidence: 'high',
    url: 'http://localhost:3000/',
    why: 'x',
    evidence: { request: 'GET /', excerpt: 'x' },
    reproduce: 'curl x',
    fixPrompt: 'x'.repeat(41),
  };

  it('ignores the origin, so a different port is the same finding', () => {
    expect(fingerprint(f)).toBe(fingerprint({ ...f, url: 'http://127.0.0.1:5173/' }));
  });

  it('ignores the count in the title', () => {
    expect(fingerprint(f)).toBe(fingerprint({ ...f, title: '3 browser security headers are missing' }));
  });

  it('ignores the random probe path used by SEC-07', () => {
    const a = { ...f, checkId: 'SEC-07', url: 'http://localhost:3000/vibeprobe-404-abc123' };
    expect(fingerprint(a)).toBe(fingerprint({ ...a, url: 'http://localhost:3000/vibeprobe-404-zzz999' }));
  });

  it('differs for another check or another path', () => {
    expect(fingerprint(f)).not.toBe(fingerprint({ ...f, checkId: 'SEC-10' }));
    expect(fingerprint(f)).not.toBe(fingerprint({ ...f, url: 'http://localhost:3000/admin' }));
  });

  it('ranks severities', () => {
    expect(meetsFailLevel('critical', 'high')).toBe(true);
    expect(meetsFailLevel('medium', 'high')).toBe(false);
    expect(meetsFailLevel('low', 'none')).toBe(false);
    expect(meetsFailLevel('low', 'low')).toBe(true);
    expect(isFailLevel('none')).toBe(true);
    expect(isFailLevel('nope')).toBe(false);
  });
});
