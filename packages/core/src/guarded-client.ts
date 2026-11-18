import { lookup as dnsLookup } from 'node:dns/promises';
import type { LookupFunction } from 'node:net';
import { Agent, Headers, fetch, type Dispatcher, type Response } from 'undici';
import { isActiveConsent, type ActiveConsent } from './active';
import { ActiveModeError, MethodNotAllowedError, RequestBudgetError, ScopeError, TooManyRedirectsError } from './errors';
import { RateLimiter } from './rate-limiter';
import { isLocalHost, type Scope } from './scope';

export type HttpMethod = 'GET' | 'HEAD' | 'OPTIONS' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

/** The only methods allowed outside --active mode (PRD: non-destructive by default). */
export const SAFE_METHODS: readonly HttpMethod[] = ['GET', 'HEAD', 'OPTIONS'];

/** What --active may add. DELETE is never sent, in any mode. */
export const ACTIVE_METHODS: readonly HttpMethod[] = [...SAFE_METHODS, 'POST', 'PUT', 'PATCH'];

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
  /** Methods this client may send. Default: GET, HEAD, OPTIONS. Anything else needs activeConsent. */
  allowedMethods?: readonly HttpMethod[];
  /** Proof that the user turned on active mode (see grantActiveConsent). Required for POST, PUT, PATCH. */
  activeConsent?: ActiveConsent;
  /** Hard cap on requests actually sent. Active mode sets one so a scan can never run away. */
  maxRequests?: number;
  /** Record write requests (and everything else) instead of sending them. Used by --plan. */
  dryRun?: boolean;
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
  /** Only sent with POST, PUT, PATCH. */
  body?: string;
  /** Default true for safe methods. Write methods never follow redirects. */
  followRedirects?: boolean;
  /** Label for the audit trail (the runner sets it to the check id). */
  tag?: string;
}

/** One request, for the audit trail in the report. */
export interface RequestRecord {
  tag?: string;
  method: HttpMethod;
  url: string;
  /** 0 when the request was only planned (--plan) and never sent. */
  status: number;
  planned?: boolean;
  body?: string;
}

/** What checks are allowed to see of the client: just "request". */
export interface HttpClient {
  request(input: string | URL, init?: GuardedRequestInit): Promise<GuardedResponse>;
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
export class GuardedHttpClient implements HttpClient {
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
  readonly #maxRequests: number;
  readonly #dryRun: boolean;
  #sent = 0;
  /** Every request, in order. Read it to build the audit trail. */
  readonly history: RequestRecord[] = [];

  constructor(options: GuardedHttpClientOptions) {
    const methods = options.allowedMethods ?? SAFE_METHODS;
    if (methods.includes('DELETE')) throw new ActiveModeError('vibeprobe never sends DELETE requests, in any mode.');
    if (methods.some((m) => !SAFE_METHODS.includes(m)) && !isActiveConsent(options.activeConsent)) {
      throw new ActiveModeError('Write methods need active mode consent. Use grantActiveConsent() (localhost only).');
    }
    this.#scope = options.scope;
    this.#maxRequests = options.maxRequests ?? Number.POSITIVE_INFINITY;
    this.#dryRun = options.dryRun ?? false;
    this.#methods = new Set(methods);
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

    const write = !SAFE_METHODS.includes(method);
    const follow = !write && (init.followRedirects ?? true);
    const first = new URL(input);
    const body = write ? init.body : undefined;
    let url = first;
    const redirects: string[] = [];

    for (;;) {
      this.#scope.assertUrl(url);
      // Defense in depth: a write request only ever goes to a loopback target, even if the scope allows more.
      if (write && !isLocalHost(url.hostname)) {
        throw new ScopeError(`${method} requests are only sent to localhost, not ${url.hostname}.`);
      }
      if (this.#dryRun) {
        this.history.push({ tag: init.tag, method, url: first.href, status: 0, planned: true, body });
        return { url: first.href, status: 0, headers: new Headers(), body: '', truncated: false, redirects };
      }
      const res = await this.#sendWithRetry(url, method, init.headers, body, write);

      const location = res.headers.get('location');
      if (follow && REDIRECT_STATUSES.has(res.status) && location) {
        await res.body?.cancel();
        if (redirects.length >= this.#maxRedirects) {
          throw new TooManyRedirectsError(`More than ${this.#maxRedirects} redirects from ${input}.`);
        }
        redirects.push(url.href);
        url = new URL(location, url);
        continue;
      }

      const read = await readCapped(res, this.#maxBodyBytes);
      this.history.push({ tag: init.tag, method, url: first.href, status: res.status, body });
      return { url: url.href, status: res.status, headers: res.headers, body: read.body, truncated: read.truncated, redirects };
    }
  }

  async close(): Promise<void> {
    await this.#dispatcher.close();
  }

  async #sendWithRetry(url: URL, method: HttpMethod, headers: Record<string, string> | undefined, body: string | undefined, write: boolean) {
    // A write request is never repeated automatically: retrying a POST could create the same data twice.
    const retries = write ? 0 : this.#maxRetries;
    for (let attempt = 0; ; attempt++) {
      await this.#limiter.take();
      if (this.#sent >= this.#maxRequests) {
        throw new RequestBudgetError(`Stopped: the limit of ${this.#maxRequests} requests for this scan was reached.`);
      }
      this.#sent++;
      const res = await this.#send(url, method, headers, body);
      if (!RETRY_STATUSES.has(res.status) || attempt >= retries) return res;
      await res.body?.cancel();
      await this.#sleep(retryDelay(res.headers.get('retry-after'), attempt));
    }
  }

  async #send(url: URL, method: HttpMethod, headers: Record<string, string> | undefined, body: string | undefined) {
    try {
      return await fetch(url, {
        method,
        body,
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

export type ActiveClientOptions = Omit<GuardedHttpClientOptions, 'allowedMethods' | 'activeConsent'> & {
  consent: ActiveConsent;
};

/** The one place a client that can send POST, PUT and PATCH is made. Needs consent; capped by default. */
export function createActiveClient({ consent, ...options }: ActiveClientOptions): GuardedHttpClient {
  return new GuardedHttpClient({ maxRequests: 1500, ...options, allowedMethods: ACTIVE_METHODS, activeConsent: consent });
}
