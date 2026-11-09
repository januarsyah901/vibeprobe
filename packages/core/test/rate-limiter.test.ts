import { describe, expect, it } from 'vitest';
import { RateLimiter } from '../src';

function fakeClock() {
  let t = 0;
  return {
    now: () => t,
    sleep: async (ms: number) => {
      t += ms;
    },
  };
}

describe('RateLimiter', () => {
  it('spaces requests at the configured rate', async () => {
    const clock = fakeClock();
    const rl = new RateLimiter({ requestsPerSecond: 5, ...clock });
    const times: number[] = [];
    for (let i = 0; i < 4; i++) {
      await rl.take();
      times.push(clock.now());
    }
    expect(times).toEqual([0, 200, 400, 600]);
  });

  it('allows an initial burst', async () => {
    const clock = fakeClock();
    const rl = new RateLimiter({ requestsPerSecond: 5, burst: 3, ...clock });
    for (let i = 0; i < 3; i++) await rl.take();
    expect(clock.now()).toBe(0);
    await rl.take();
    expect(clock.now()).toBe(200);
  });

  it('rejects a non-positive rate', () => {
    expect(() => new RateLimiter({ requestsPerSecond: 0 })).toThrow(RangeError);
  });
});
