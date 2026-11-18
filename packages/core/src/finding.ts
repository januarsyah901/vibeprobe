import { z } from 'zod';

export const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;
export const CONFIDENCES = ['high', 'medium', 'low'] as const;

export const FindingSchema = z.object({
  /** SEC-nn are passive checks (read-only); ACT-nn need --active. */
  checkId: z.string().regex(/^(SEC|ACT)-\d{2}$/),
  title: z.string().min(1),
  severity: z.enum(SEVERITIES),
  /** high only with direct proof (e.g. a 200 response with the data); pattern-only guesses are low. */
  confidence: z.enum(CONFIDENCES),
  url: z.string(),
  /** Why this is dangerous, at most two sentences, plain language. */
  why: z.string().min(1),
  evidence: z.object({
    request: z.string(),
    status: z.number().int().optional(),
    /** Already masked. */
    excerpt: z.string(),
  }),
  /** A curl that repeats the check (read-only for SEC checks; ACT checks use the same method they sent). */
  reproduce: z.string(),
  /** Ready to paste into an AI coding tool. Filled from a template, never by an LLM. */
  fixPrompt: z.string().min(1),
});

export type Finding = z.infer<typeof FindingSchema>;
export type Severity = (typeof SEVERITIES)[number];
export type Confidence = (typeof CONFIDENCES)[number];

export function curlFor(url: string, headers: Record<string, string> = {}): string {
  const h = Object.entries(headers)
    .map(([k, v]) => ` -H '${k}: ${v}'`)
    .join('');
  return `curl -sS -i${h} '${url}'`;
}

const shq = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;

/** curl for a request that is not a plain GET (used by active checks). */
export function curlWrite(method: string, url: string, opts: { headers?: Record<string, string>; body?: string } = {}): string {
  const h = Object.entries(opts.headers ?? {})
    .map(([k, v]) => ` -H ${shq(`${k}: ${v}`)}`)
    .join('');
  const b = opts.body === undefined ? '' : ` --data-raw ${shq(opts.body)}`;
  return `curl -sS -i -X ${method}${h}${b} ${shq(url)}`;
}
