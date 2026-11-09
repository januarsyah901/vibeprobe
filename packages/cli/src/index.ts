import { mkdir, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { GuardedHttpClient, Scope, ScopeError, VibeprobeError, crawl, runChecks } from '@vibeprobe/core';
import { allChecks } from '@vibeprobe/checks';
import { version } from '../package.json';
import { summary, toMarkdown } from './report';
import { toHtml } from './report-html';
import { BaselineError, FAIL_LEVELS, fingerprint, isFailLevel, loadBaseline, meetsFailLevel, writeBaseline } from './baseline';

const HELP = `vibeprobe ${version}
Local security scanner for apps built with AI. Scans apps you own, read-only.

Usage
  npx vibeprobe <url>

Example
  npx vibeprobe http://localhost:3000

Options
  --recheck <ID>          Run only one check (e.g. SEC-01) to see whether your fix worked
  --fail-on <level>       Exit 1 only for findings at or above: critical, high, medium, low (default), none
  --baseline <file>       Ignore findings already accepted in this file; report and fail only on new ones
  --write-baseline <file> Save the current findings as accepted and exit 0
  --out <dir>             Where to write reports (default: ./vibeprobe-report)
  --rate <n>              Max requests per second (default: 5)
  -h, --help              Show this help
  -v, --version           Show the version

Only localhost targets are allowed in this version.
Reports are written to ./vibeprobe-report/ (report.html, report.md, report.json), or --out <dir>.
Exit code: 0 clean, 1 findings (low-confidence ones do not count) or error, 2 bad input or out of scope.
In CI: npx vibeprobe <url> --fail-on high --baseline .vibeprobe-baseline.json`;

export async function main(argv: string[]): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        help: { type: 'boolean', short: 'h' },
        version: { type: 'boolean', short: 'v' },
        recheck: { type: 'string' },
        'fail-on': { type: 'string' },
        baseline: { type: 'string' },
        'write-baseline': { type: 'string' },
        out: { type: 'string' },
        rate: { type: 'string' },
      },
    });
  } catch (err) {
    console.error((err as Error).message);
    console.error('Run vibeprobe --help for usage.');
    return 2;
  }

  const { values, positionals } = parsed;
  if (values.version) {
    console.log(version);
    return 0;
  }
  if (values.help || positionals.length === 0) {
    console.log(HELP);
    return positionals.length === 0 && !values.help ? 2 : 0;
  }
  if (positionals.length > 1) {
    console.error('Give exactly one target URL.');
    return 2;
  }

  let target: URL;
  try {
    target = new URL(positionals[0]!);
  } catch {
    console.error(`Not a valid URL: ${positionals[0]}. Example: http://localhost:3000`);
    return 2;
  }

  const failOn = values['fail-on'] ?? 'low';
  if (!isFailLevel(failOn)) {
    console.error(`Invalid --fail-on "${failOn}". Use one of: ${FAIL_LEVELS.join(', ')}.`);
    return 2;
  }
  const rate = values.rate === undefined ? 5 : Number(values.rate);
  if (!Number.isFinite(rate) || rate <= 0 || rate > 1000) {
    console.error(`Invalid --rate "${values.rate}". Use a number between 0 and 1000 (default 5).`);
    return 2;
  }
  let accepted = new Set<string>();
  if (values.baseline !== undefined) {
    try {
      accepted = await loadBaseline(values.baseline);
    } catch (err) {
      if (err instanceof BaselineError) {
        console.error(err.message);
        return 2;
      }
      throw err;
    }
  }

  let checks = allChecks;
  if (values.recheck !== undefined) {
    const wanted = values.recheck.toUpperCase();
    const match = allChecks.find((c) => c.id === wanted);
    if (!match) {
      console.error(`Unknown check "${values.recheck}". Available: ${allChecks.map((c) => c.id).join(', ')}.`);
      return 2;
    }
    checks = [match];
  }
  const recheck = checks.length === 1 && values.recheck !== undefined;

  const client = new GuardedHttpClient({ scope: new Scope(), requestsPerSecond: rate, userAgent: `vibeprobe/${version}` });
  try {
    console.log(`Scanning ${target.href} (read-only, localhost only)...`);
    const surface = await crawl(client, target);
    console.log(
      `Mapped ${surface.pages.length} page(s), ${surface.scripts.length} script(s), ${surface.endpoints.length} endpoint(s)` +
        (surface.framework !== 'unknown' ? ` (${surface.framework})` : '') +
        (surface.isDevServer ? '. Dev server detected: production-only checks are skipped.' : '.'),
    );
    const run = await runChecks(checks, { client, surface, target });
    const errors = run.errors;
    // Findings already accepted in the baseline are left out of the report and never fail the run.
    const findings = run.findings.filter((f) => !accepted.has(fingerprint(f)));
    const acceptedCount = run.findings.length - findings.length;
    if (acceptedCount > 0) console.log(`\n${acceptedCount} finding${acceptedCount > 1 ? 's' : ''} accepted by baseline, not shown.`);
    for (const f of findings) {
      console.log(`\n[${f.severity.toUpperCase()}] ${f.title} (${f.checkId}, confidence ${f.confidence})\n  ${f.url}`);
    }
    for (const e of errors) console.error(`Check ${e.checkId} failed: ${e.message}`);
    // Low-confidence findings are shown but never fail a run (PRD).
    if (values['write-baseline'] !== undefined) {
      const saved = run.findings.filter((f) => f.confidence !== 'low');
      await writeBaseline(values['write-baseline'], saved);
      console.log(`\nSaved ${saved.length} finding${saved.length === 1 ? '' : 's'} to ${values['write-baseline']} as accepted. Commit this file.`);
      return errors.length > 0 ? 1 : 0;
    }
    const failing = findings.filter((f) => f.confidence !== 'low' && meetsFailLevel(f.severity, failOn));
    if (recheck) {
      const id = checks[0]!.id;
      if (errors.length > 0) return 1;
      console.log(
        failing.length === 0
          ? `\n${id}: no problems found. Looks fixed.`
          : `\n${id}: still ${failing.length} problem${failing.length > 1 ? 's' : ''}. Apply the fix prompt and run again.`,
      );
      return failing.length > 0 ? 1 : 0;
    }
    const outDir = values.out ?? 'vibeprobe-report';
    const dir = resolve(outDir);
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, 'report.json'), JSON.stringify({ version, target: target.href, findings, errors }, null, 2));
    await writeFile(join(dir, 'report.md'), toMarkdown(target.href, findings));
    await writeFile(join(dir, 'report.html'), toHtml(findings, { target: target.href, version, generatedAt: new Date() }));
    console.log(`\n${summary(findings)}. Report: ${join(outDir, 'report.html')}`);
    return failing.length > 0 || errors.length > 0 ? 1 : 0;
  } catch (err) {
    if (err instanceof ScopeError) {
      console.error(`Refused: ${err.message}`);
      return 2;
    }
    if (err instanceof VibeprobeError) {
      console.error(err.message);
      return 1;
    }
    const cause = (err as { cause?: { code?: string; message?: string } }).cause;
    const reason = cause?.code ?? cause?.message ?? (err as Error).message;
    console.error(`Could not reach ${target.href} (${reason}).`);
    console.error('Is your app running?');
    return 1;
  } finally {
    await client.close();
  }
}
