import { lookup as dnsLookup } from 'node:dns/promises';
import type { LookupFunction } from 'node:net';
import { Agent, fetch, type Dispatcher, type Headers, type Response } from 'undici';
import { MethodNotAllowedError, ScopeError, TooManyRedirectsError } from './errors';
import { RateLimiter } from './rate-limiter';
import type { Scope } from './scope';

export type HttpMethod = 'GET' | 'HEAD' | 'OPTIONS' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

/** The only methods allowed outside --active mode (PRD: non-destructive by default). */
export const SAFE_METHODS: readonly HttpMethod[] = ['GET', 'HEAD', 'OPTIONS'];

export interface ResolvedAddress {
  address: string;
  family: number;
}

/** Resolves a hostname to every address it maps to. Injected in tests. */
export type Resolver = (hostname: string) => Promise<ResolvedAddress[]>;

const systemResolver: Resolver = (hostname) => dnsLookup(hostname, { all: true, verbatim: true });

export interface GuardedHttpClientOptions {
  scope: Scope;
  /** Default 5 (PRD guardrail). */
  requestsPerSecond?: number;
  /** Methods this client may send. Default: GET, HEAD, OPTIONS. */
  allowedMethods?: readonly HttpMethod[];
  /** Default 5. Every hop is checked against the scope again. */
  maxRedirects?: number;
  /** Retries after 429/503. Default 2. */
  maxRetries?: number;
  /** Per-request timeout. Default 15 s. */
  timeoutMs?: number;
  /** Response bodies are cut off after this many bytes. Default 5 MiB. */
  maxBodyBytes?: number;
  userAgent?: string;
  resolver?: Resolver;
  sleep?: (ms: number) => Promise<void>;
}

export interface GuardedRequestInit {
  method?: HttpMethod;
  headers?: Record<string, string>;
}

export interface GuardedResponse {
  /** Final URL after redirects. */
  url: string;
  status: number;
  headers: Headers;
  body: string;
  /** True if the body was cut off at maxBodyBytes. */
  truncated: boolean;
  /** Every URL visited before the final one, in order. */
  redirects: string[];
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const RETRY_STATUSES = new Set([429, 503]);
const MAX_RETRY_DELAY_MS = 30_000;
const defaultSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/**
 * The single exit door for network traffic in vibeprobe. Nothing else in the codebase may
 * talk to the network (enforced by lint). It refuses, before sending anything:
 * - methods outside the allowed set,
 * - URLs outside the scope, including on every redirect hop,
 * - hostnames that resolve to an address the scope forbids, checked at connect time so the
 *   address that is checked is the address that is used.
 */
export class GuardedHttpClient {
  readonly #scope: Scope;
  readonly #methods: ReadonlySet<HttpMethod>;
  readonly #maxRedirects: number;
  readonly #maxRetries: number;
  readonly #timeoutMs: number;
  readonly #maxBodyBytes: number;
  readonly #userAgent: string;
  readonly #limiter: RateLimiter;
  readonly #sleep: (ms: number) => Promise<void>;
  readonly #dispatcher: Dispatcher;

  constructor(options: GuardedHttpClientOptions) {
    this.#scope = options.scope;
    this.#methods = new Set(options.allowedMethods ?? SAFE_METHODS);
    this.#maxRedirects = options.maxRedirects ?? 5;
    this.#maxRetries = options.maxRetries ?? 2;
    this.#timeoutMs = options.timeoutMs ?? 15_000;
    this.#maxBodyBytes = options.maxBodyBytes ?? 5 * 1024 * 1024;
    this.#userAgent = options.userAgent ?? 'vibeprobe';
    this.#sleep = options.sleep ?? defaultSleep;
    this.#limiter = new RateLimiter({
      requestsPerSecond: options.requestsPerSecond ?? 5,
      sleep: this.#sleep,
    });
    this.#dispatcher = new Agent({
      connect: { lookup: guardedLookup(this.#scope, options.resolver ?? systemResolver) },
    });
  }

  async request(input: string | URL, init: GuardedRequestInit = {}): Promise<GuardedResponse> {
    const method = (init.method ?? 'GET').toUpperCase() as HttpMethod;
    if (!this.#methods.has(method)) {
      throw new MethodNotAllowedError(
        `${method} is not allowed in this mode. Allowed: ${[...this.#methods].join(', ')}.`,
      );
    }

    let url = new URL(input);
    const redirects: string[] = [];

    for (;;) {
      this.#scope.assertUrl(url);
      const res = await this.#sendWithRetry(url, method, init.headers);

      const location = res.headers.get('location');
      if (REDIRECT_STATUSES.has(res.status) && location) {
        await res.body?.cancel();
        if (redirects.length >= this.#maxRedirects) {
          throw new TooManyRedirectsError(`More than ${this.#maxRedirects} redirects from ${input}.`);
        }
        redirects.push(url.href);
        url = new URL(location, url);
        continue;
      }

      const { body, truncated } = await readCapped(res, this.#maxBodyBytes);
      return { url: url.href, status: res.status, headers: res.headers, body, truncated, redirects };
    }
  }

  async close(): Promise<void> {
    await this.#dispatcher.close();
  }

  async #sendWithRetry(url: URL, method: HttpMethod, headers?: Record<string, string>) {
    for (let attempt = 0; ; attempt++) {
      await this.#limiter.take();
      const res = await this.#send(url, method, headers);
      if (!RETRY_STATUSES.has(res.status) || attempt >= this.#maxRetries) return res;
      await res.body?.cancel();
      await this.#sleep(retryDelay(res.headers.get('retry-after'), attempt));
    }
  }

  async #send(url: URL, method: HttpMethod, headers?: Record<string, string>) {
    try {
      return await fetch(url, {
        method,
        headers: { 'user-agent': this.#userAgent, ...headers },
        redirect: 'manual',
        dispatcher: this.#dispatcher,
        signal: AbortSignal.timeout(this.#timeoutMs),
      });
    } catch (err) {
      // The connect-time lookup throws ScopeError; undici wraps it. Surface the real reason.
      const scopeErr = findCause(err, ScopeError);
      if (scopeErr) throw scopeErr;
      throw err;
    }
  }
}

function guardedLookup(scope: Scope, resolve: Resolver): LookupFunction {
  return (hostname, options, callback) => {
    void (async () => {
      try {
        const addrs = await resolve(hostname);
        if (addrs.length === 0) throw new ScopeError(`${hostname} did not resolve to any address.`);
        for (const a of addrs) scope.assertResolvedAddress(hostname, a.address);
        if (options.all) {
          callback(null, addrs);
        } else {
          const first = addrs.find((a) => !options.family || a.family === options.family) ?? addrs[0]!;
          callback(null, first.address, first.family);
        }
      } catch (err) {
        callback(err as NodeJS.ErrnoException, '', 0);
      }
    })();
  };
}

function retryDelay(retryAfter: string | null, attempt: number): number {
  if (retryAfter !== null) {
    const seconds = Number(retryAfter);
    if (Number.isFinite(seconds) && seconds >= 0) return Math.min(seconds * 1000, MAX_RETRY_DELAY_MS);
    const date = Date.parse(retryAfter);
    if (!Number.isNaN(date)) return Math.min(Math.max(0, date - Date.now()), MAX_RETRY_DELAY_MS);
  }
  return Math.min(1000 * 2 ** attempt, MAX_RETRY_DELAY_MS);
}

async function readCapped(res: Response, maxBytes: number) {
  if (!res.body) return { body: '', truncated: false };
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  let truncated = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (size + value.byteLength > maxBytes) {
      chunks.push(value.subarray(0, maxBytes - size));
      truncated = true;
      await reader.cancel();
      break;
    }
    chunks.push(value);
    size += value.byteLength;
  }
  return { body: Buffer.concat(chunks).toString('utf8'), truncated };
}

function findCause<T extends Error>(err: unknown, type: new (...args: never[]) => T): T | undefined {
  let cur: unknown = err;
  for (let depth = 0; cur && depth < 5; depth++) {
    if (cur instanceof type) return cur;
    cur = (cur as { cause?: unknown }).cause;
  }
  return undefined;
}
