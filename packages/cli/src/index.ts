import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { GuardedHttpClient, Scope, ScopeError, VibeprobeError, crawl, runChecks } from '@vibeprobe/core';
import { allChecks } from '@vibeprobe/checks';
import { version } from '../package.json';
import { summary, toMarkdown } from './report';

const HELP = `vibeprobe ${version}
Local security scanner for apps built with AI. Scans apps you own, read-only.

Usage
  npx vibeprobe <url>

Example
  npx vibeprobe http://localhost:3000

Options
  --recheck <ID>  Run only one check (e.g. SEC-01) to see whether your fix worked
  -h, --help      Show this help
  -v, --version   Show the version

Only localhost targets are allowed in this version.
Reports are written to ./vibeprobe-report/ (report.json and report.md).
Exit code: 0 clean, 1 findings (low-confidence ones do not count) or error, 2 bad input or out of scope.`;

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

  const client = new GuardedHttpClient({ scope: new Scope(), userAgent: `vibeprobe/${version}` });
  try {
    console.log(`Scanning ${target.href} (read-only, localhost only)...`);
    const surface = await crawl(client, target);
    console.log(
      `Mapped ${surface.pages.length} page(s), ${surface.scripts.length} script(s), ${surface.endpoints.length} endpoint(s)` +
        (surface.framework !== 'unknown' ? ` (${surface.framework})` : '') +
        (surface.isDevServer ? '. Dev server detected: production-only checks are skipped.' : '.'),
    );
    const { findings, errors } = await runChecks(checks, { client, surface, target });
    for (const f of findings) {
      console.log(`\n[${f.severity.toUpperCase()}] ${f.title} (${f.checkId}, confidence ${f.confidence})\n  ${f.url}`);
    }
    for (const e of errors) console.error(`Check ${e.checkId} failed: ${e.message}`);
    // Low-confidence findings are shown but never fail a run (PRD).
    const failing = findings.filter((f) => f.confidence !== 'low');
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
    const dir = join(process.cwd(), 'vibeprobe-report');
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, 'report.json'), JSON.stringify({ version, target: target.href, findings, errors }, null, 2));
    await writeFile(join(dir, 'report.md'), toMarkdown(target.href, findings));
    console.log(`\n${summary(findings)}. Report: ${join('vibeprobe-report', 'report.md')}`);
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
