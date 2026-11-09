import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { SEVERITIES, type Finding, type Severity } from '@vibeprobe/core';

export const FAIL_LEVELS = [...SEVERITIES, 'none'] as const;
export type FailLevel = (typeof FAIL_LEVELS)[number];

const RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };

export function isFailLevel(v: string): v is FailLevel {
  return (FAIL_LEVELS as readonly string[]).includes(v);
}

/** True when a finding of this severity should fail the run at the given --fail-on level. */
export function meetsFailLevel(severity: Severity, level: FailLevel): boolean {
  return level !== 'none' && RANK[severity] >= RANK[level];
}

/**
 * A stable ID for a finding. It ignores the origin (so a changed port does not matter), digits in the
 * title (so "4 headers missing" and "3 headers missing" stay the same finding) and random probe paths.
 */
export function fingerprint(f: Finding): string {
  let path = f.url;
  try {
    path = new URL(f.url).pathname;
  } catch {
    /* keep raw */
  }
  // SEC-04 and SEC-07 probe a random path each run; it must not make the same finding look new.
  path = path.replace(/vibeprobe-404-[a-z0-9]+/g, 'vibeprobe-404-*');
  return createHash('sha256').update(`${f.checkId}|${path}|${f.title.replace(/\d+/g, '#')}`).digest('hex').slice(0, 16);
}

interface BaselineFile {
  version: 1;
  findings: { fingerprint: string; checkId: string; title: string; path: string }[];
}

export class BaselineError extends Error {}

export async function loadBaseline(path: string): Promise<Set<string>> {
  let raw: string;
  try {
    raw = await readFile(path, 'utf8');
  } catch {
    throw new BaselineError(`Baseline file not found: ${path}. Create one with --write-baseline ${path}`);
  }
  try {
    const data = JSON.parse(raw) as Partial<BaselineFile>;
    if (data.version !== 1 || !Array.isArray(data.findings)) throw new Error('bad shape');
    return new Set(data.findings.map((f) => String(f.fingerprint)));
  } catch {
    throw new BaselineError(`${path} is not a valid vibeprobe baseline file.`);
  }
}

export async function writeBaseline(path: string, findings: Finding[]): Promise<void> {
  const file: BaselineFile = {
    version: 1,
    findings: findings.map((f) => ({
      fingerprint: fingerprint(f),
      checkId: f.checkId,
      title: f.title,
      path: (() => {
        try {
          return new URL(f.url).pathname;
        } catch {
          return f.url;
        }
      })(),
    })),
  };
  await writeFile(path, JSON.stringify(file, null, 2) + '\n');
}
