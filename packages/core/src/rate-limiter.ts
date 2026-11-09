export interface RateLimiterOptions {
  /** Steady-state requests per second. */
  requestsPerSecond: number;
  /** How many requests may go out back-to-back before throttling kicks in. Defaults to 1. */
  burst?: number;
  /** Injected for tests. */
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
}

const defaultSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** Token bucket. `take()` resolves when the caller may send one request. */
export class RateLimiter {
  readonly #rate: number;
  readonly #capacity: number;
  readonly #now: () => number;
  readonly #sleep: (ms: number) => Promise<void>;
  #tokens: number;
  #last: number;
  #queue: Promise<void> = Promise.resolve();

  constructor(options: RateLimiterOptions) {
    if (!(options.requestsPerSecond > 0)) {
      throw new RangeError('requestsPerSecond must be greater than 0');
    }
    this.#rate = options.requestsPerSecond / 1000;
    this.#capacity = Math.max(1, options.burst ?? 1);
    this.#now = options.now ?? Date.now;
    this.#sleep = options.sleep ?? defaultSleep;
    this.#tokens = this.#capacity;
    this.#last = this.#now();
  }

  take(): Promise<void> {
    // Serialize callers so concurrent requests cannot share one token.
    const next = this.#queue.then(() => this.#takeOne());
    this.#queue = next.catch(() => {});
    return next;
  }

  async #takeOne(): Promise<void> {
    for (;;) {
      const now = this.#now();
      this.#tokens = Math.min(this.#capacity, this.#tokens + (now - this.#last) * this.#rate);
      this.#last = now;
      if (this.#tokens >= 1) {
        this.#tokens -= 1;
        return;
      }
      await this.#sleep(Math.ceil((1 - this.#tokens) / this.#rate));
    }
  }
}
