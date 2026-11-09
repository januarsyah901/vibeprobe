import { z } from 'zod';

export const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;
export const CONFIDENCES = ['high', 'medium', 'low'] as const;

export const FindingSchema = z.object({
  checkId: z.string().regex(/^SEC-\d{2}$/),
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
  /** A read-only curl that repeats the check. */
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
