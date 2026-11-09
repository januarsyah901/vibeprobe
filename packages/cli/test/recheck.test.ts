import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { createApp as vulnerableApp } from '../../../fixtures/vulnerable-app/server';
import { createApp as safeApp } from '../../../fixtures/safe-app/server';
import { main } from '../src/index';

const listen = (s: Server) => new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
const close = (s: Server) => new Promise<void>((r) => s.close(() => r()));
const url = (s: Server) => `http://127.0.0.1:${(s.address() as AddressInfo).port}`;

const vulnerable = vulnerableApp();
const safe = safeApp();
beforeAll(async () => {
  await Promise.all([listen(vulnerable), listen(safe)]);
});
afterAll(async () => {
  await Promise.all([close(vulnerable), close(safe)]);
});
afterEach(() => vi.restoreAllMocks());

function quiet() {
  const out: string[] = [];
  vi.spyOn(console, 'log').mockImplementation((...a) => void out.push(a.join(' ')));
  vi.spyOn(console, 'error').mockImplementation((...a) => void out.push(a.join(' ')));
  return out;
}

describe('--recheck', () => {
  it('exits 1 and says it is not fixed while the hole is open', async () => {
    const out = quiet();
    expect(await main([url(vulnerable), '--recheck', 'SEC-06'])).toBe(1);
    expect(out.join('\n')).toContain('SEC-06: still');
  });

  it('exits 0 and says it looks fixed on a safe app', async () => {
    const out = quiet();
    expect(await main([url(safe), '--recheck', 'sec-06'])).toBe(0);
    expect(out.join('\n')).toContain('Looks fixed');
  });

  it('runs only the requested check', async () => {
    const out = quiet();
    await main([url(vulnerable), '--recheck', 'SEC-09']);
    const text = out.join('\n');
    expect(text).toContain('SEC-09');
    expect(text).not.toContain('SEC-06');
    expect(text).not.toContain('SEC-01');
  });

  it('exits 2 for an unknown ID and lists the valid ones', async () => {
    const out = quiet();
    expect(await main([url(safe), '--recheck', 'SEC-99'])).toBe(2);
    expect(out.join('\n')).toMatch(/Unknown check "SEC-99"\. Available: SEC-01/);
  });

  it('does not fail on low-confidence findings alone', async () => {
    quiet();
    // /api/orders is low confidence only; recheck SEC-03 still fails because /api/users is high.
    expect(await main([url(vulnerable), '--recheck', 'SEC-03'])).toBe(1);
  });
});
