import type { Canary } from './canary';
import type { GuardedRequestInit, GuardedResponse, HttpClient } from './guarded-client';
import type { Finding, Severity } from './finding';
import { FindingSchema } from './finding';
import type { SurfaceMap } from './surface';

export interface CheckContext {
  client: HttpClient;
  surface: SurfaceMap;
  target: URL;
  /** Present only in --active runs that include a check which needs it (SSRF). */
  canary?: Canary;
}

/** A check is a small, self-contained module (PRD F4). It may only read through ctx.client. */
export interface Check {
  id: string;
  title: string;
  severity: Severity;
  /** passive (default): read-only, always runs. active: sends test payloads, only with --active. */
  mode?: 'passive' | 'active';
  /** Active checks only: light runs in --active, full adds the heavier ones. Default light. */
  intensity?: 'light' | 'full';
  run(ctx: CheckContext): Promise<Finding[]>;
}

/** Labels every request with the check that made it, for the audit trail. */
class TaggedClient implements HttpClient {
  readonly #inner: HttpClient;
  readonly #tag: string;
  constructor(inner: HttpClient, tag: string) {
    this.#inner = inner;
    this.#tag = tag;
  }
  request(input: string | URL, init: GuardedRequestInit = {}): Promise<GuardedResponse> {
    return this.#inner.request(input, { ...init, tag: init.tag ?? this.#tag });
  }
}

export interface CheckError {
  checkId: string;
  message: string;
}

export interface RunResult {
  findings: Finding[];
  errors: CheckError[];
}

export interface RunOptions {
  timeoutMs?: number;
  concurrency?: number;
}

const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const CONFIDENCE_ORDER = { high: 0, medium: 1, low: 2 } as const;

/** Runs checks with a per-check timeout. One check that throws never takes the scan down. */
export async function runChecks(checks: Check[], ctx: CheckContext, options: RunOptions = {}): Promise<RunResult> {
  const timeoutMs = options.timeoutMs ?? 60_000;
  const concurrency = Math.max(1, options.concurrency ?? 4);
  const findings: Finding[] = [];
  const errors: CheckError[] = [];
  let next = 0;

  async function worker() {
    while (next < checks.length) {
      const check = checks[next++]!;
      try {
        const out = await withTimeout(check.run({ ...ctx, client: new TaggedClient(ctx.client, check.id) }), timeoutMs, `${check.id} timed out after ${timeoutMs} ms`);
        for (const f of out) findings.push(FindingSchema.parse(f));
      } catch (err) {
        errors.push({ checkId: check.id, message: (err as Error).message });
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, checks.length) }, worker));

  const seen = new Set<string>();
  const unique = findings.filter((f) => {
    const key = `${f.checkId}|${f.url}|${f.title}`;
    return seen.has(key) ? false : (seen.add(key), true);
  });
  unique.sort(
    (a, b) =>
      SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
      CONFIDENCE_ORDER[a.confidence] - CONFIDENCE_ORDER[b.confidence] ||
      a.checkId.localeCompare(b.checkId),
  );
  return { findings: unique, errors };
}

function withTimeout<T>(p: Promise<T>, ms: number, message: string): Promise<T> {
  let timer: NodeJS.Timeout;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(message)), ms);
  });
  return Promise.race([p, timeout]).finally(() => clearTimeout(timer));
}
