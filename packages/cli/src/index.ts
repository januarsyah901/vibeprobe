import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { parseArgs } from 'node:util';
import {
  ActiveModeError,
  GuardedHttpClient,
  SEVERITIES,
  Scope,
  ScopeError,
  VibeprobeError,
  crawl,
  createActiveClient,
  grantActiveConsent,
  isLocalHost,
  runChecks,
  startCanary,
  type Canary,
  type Check,
  type Finding,
  type RequestRecord,
  type RunResult,
} from '@vibeprobe/core';
import { activeChecks, activeChecksFor, allChecks, type ActiveIntensity } from '@vibeprobe/checks';
import { version } from '../package.json';
import { summary, toMarkdown } from './report';
import { toHtml } from './report-html';
import { toSarif } from './sarif';
import { BaselineError, FAIL_LEVELS, fingerprint, isFailLevel, loadBaseline, meetsFailLevel, writeBaseline } from './baseline';

const HELP = `vibeprobe ${version}
Local security scanner for apps built with AI. Scans apps you own.

Usage
  npx vibeprobe <url>

Example
  npx vibeprobe http://localhost:3000

Modes
  (default)               Read-only: only GET, HEAD and OPTIONS. Safe to run anywhere you own.
  --active [light|full]   Also sends test payloads (POST, PUT, PATCH) to look for XSS, SQL injection,
                          missing logins on write endpoints and more. localhost only. Can leave junk
                          data in your database: use a dev database. light (default) is the low-noise
                          set, full adds everything. Asks for confirmation (or pass --yes).
  --plan                  With --active: list every request that would be sent, send none of them.

Options
  --recheck <ID>          Run only one check (e.g. SEC-01, or ACT-01 with --active) to see whether your fix worked
  --yes, -y               Confirm active mode without asking (needed in CI)
  --sarif <file>          Also write a SARIF file for GitHub code scanning
  --fail-on <level>       Exit 1 only for findings at or above: critical, high, medium, low (default), none
  --baseline <file>       Ignore findings already accepted in this file; report and fail only on new ones
  --write-baseline <file> Save the current findings as accepted and exit 0
  --out <dir>             Where to write reports (default: ./vibeprobe-report)
  --rate <n>              Max requests per second (default: 5)
  -h, --help              Show this help
  -v, --version           Show the version

Only localhost targets are allowed in this version; active mode never leaves localhost and never sends DELETE.
Reports are written to ./vibeprobe-report/ (report.html, report.md, report.json), or --out <dir>.
Exit code: 0 clean, 1 findings (low-confidence ones do not count) or error, 2 bad input or out of scope.
In CI: npx vibeprobe <url> --fail-on high --baseline .vibeprobe-baseline.json
Active in CI: npx vibeprobe <url> --active full --yes --fail-on high`;

/** `--active` alone means light; `--active full` and `--active=full` both work. */
export function normalizeArgv(argv: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a !== '--active') {
      out.push(a);
      continue;
    }
    const next = argv[i + 1];
    if (next === 'light' || next === 'full') {
      out.push(`--active=${next}`);
      i++;
    } else {
      out.push('--active=light');
    }
  }
  return out;
}

const RANK = Object.fromEntries(SEVERITIES.map((s, i) => [s, i])) as Record<Finding['severity'], number>;
const CONF = { high: 0, medium: 1, low: 2 } as const;
const bySeverity = (a: Finding, b: Finding) => RANK[a.severity] - RANK[b.severity] || CONF[a.confidence] - CONF[b.confidence] || a.checkId.localeCompare(b.checkId);

async function confirmActive(target: URL, intensity: ActiveIntensity): Promise<boolean> {
  if (!process.stdin.isTTY || !process.stdout.isTTY) return false;
  console.log(
    `\nActive mode (${intensity}) will send test payloads (POST, PUT, PATCH with attack-like input) to ${target.origin}.\n` +
      'It can leave junk data in your database: use a development database, never production.\n' +
      'It only runs against localhost, never sends DELETE, and lists every request in the report.\n',
  );
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = await rl.question('Continue? [y/N] ');
    return /^y(es)?$/i.test(answer.trim());
  } finally {
    rl.close();
  }
}

export async function main(rawArgv: string[]): Promise<number> {
  const argv = normalizeArgv(rawArgv);
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
        active: { type: 'string' },
        yes: { type: 'boolean', short: 'y' },
        plan: { type: 'boolean' },
        sarif: { type: 'string' },
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
  const activeMode = values.active !== undefined;
  const intensity = (values.active ?? 'light') as ActiveIntensity;
  if (activeMode && intensity !== 'light' && intensity !== 'full') {
    console.error(`Invalid --active "${values.active}". Use light or full.`);
    return 2;
  }
  if (values.plan && !activeMode) {
    console.error('--plan needs --active: it lists the requests active mode would send.');
    return 2;
  }
  if (activeMode && !isLocalHost(target.hostname)) {
    console.error(`Refused: active mode only runs against localhost, not ${target.hostname}.`);
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

  let passiveChecks: Check[] = allChecks;
  let activeList: Check[] = activeMode ? activeChecksFor(intensity) : [];
  let recheckId: string | undefined;
  if (values.recheck !== undefined) {
    const wanted = values.recheck.toUpperCase();
    const match = [...allChecks, ...activeChecks].find((c) => c.id === wanted);
    if (!match) {
      console.error(`Unknown check "${values.recheck}". Available: ${[...allChecks, ...activeChecks].map((c) => c.id).join(', ')}.`);
      return 2;
    }
    if (match.mode === 'active' && !activeMode) {
      console.error(`${match.id} is an active check: it sends test payloads. Add --active to run it, for example: vibeprobe ${target.origin} --active --recheck ${match.id}`);
      return 2;
    }
    recheckId = match.id;
    passiveChecks = match.mode === 'active' ? [] : [match];
    activeList = match.mode === 'active' ? [match] : [];
  }
  if (values.plan) passiveChecks = [];
  const recheck = recheckId !== undefined;

  if (activeMode && !values.plan && !values.yes && !(await confirmActive(target, intensity))) {
    console.error(
      process.stdin.isTTY && process.stdout.isTTY
        ? 'Cancelled. Nothing was sent.'
        : 'Active mode needs your confirmation. Run it in a terminal and answer y, or pass --yes (for CI).',
    );
    return 2;
  }

  const client = new GuardedHttpClient({ scope: new Scope(), requestsPerSecond: rate, userAgent: `vibeprobe/${version}` });
  try {
    console.log(`Scanning ${target.href} (${activeMode ? `active mode ${intensity}, localhost only` : 'read-only, localhost only'})...`);
    const surface = await crawl(client, target);
    console.log(
      `Mapped ${surface.pages.length} page(s), ${surface.scripts.length} script(s), ${surface.endpoints.length} endpoint(s)` +
        (surface.framework !== 'unknown' ? ` (${surface.framework})` : '') +
        (surface.isDevServer ? '. Dev server detected: production-only checks are skipped.' : '.'),
    );
    const passiveRun: RunResult = passiveChecks.length > 0 ? await runChecks(passiveChecks, { client, surface, target }) : { findings: [], errors: [] };
    let activeRun: RunResult = { findings: [], errors: [] };
    let requests: RequestRecord[] = [];
    if (activeList.length > 0) {
      const consent = grantActiveConsent({ target, acknowledged: true });
      const activeClient = createActiveClient({ scope: new Scope(), consent, requestsPerSecond: rate, userAgent: `vibeprobe/${version}`, dryRun: values.plan === true });
      const canary: Canary | undefined = activeList.some((c) => c.id === 'ACT-10') ? await startCanary() : undefined;
      try {
        console.log(values.plan ? '\nPlanning active checks. Nothing is sent.' : `\nActive mode (${intensity}): sending test payloads to ${target.origin}...`);
        activeRun = await runChecks(activeList, { client: activeClient, surface, target, canary });
        requests = [...activeClient.history];
      } finally {
        await canary?.close();
        await activeClient.close();
      }
    }
    if (values.plan) {
      console.log(`\nPlan: ${requests.length} request${requests.length === 1 ? '' : 's'} would be sent. None were.`);
      for (const r of requests) console.log(`  ${(r.tag ?? '').padEnd(7)} ${r.method.padEnd(5)} ${r.url}${r.body ? `   ${r.body.slice(0, 120)}` : ''}`);
      for (const e of activeRun.errors) console.error(`Check ${e.checkId} failed: ${e.message}`);
      console.log('\nThe page crawl above was read-only. Passive checks are skipped in --plan.');
      return activeRun.errors.length > 0 ? 1 : 0;
    }
    const run: RunResult = {
      findings: [...passiveRun.findings, ...activeRun.findings].sort(bySeverity),
      errors: [...passiveRun.errors, ...activeRun.errors],
    };
    const errors = run.errors;
    // Findings already accepted in the baseline are left out of the report and never fail the run.
    const findings = run.findings.filter((f) => !accepted.has(fingerprint(f)));
    const acceptedCount = run.findings.length - findings.length;
    if (acceptedCount > 0) console.log(`\n${acceptedCount} finding${acceptedCount > 1 ? 's' : ''} accepted by baseline, not shown.`);
    for (const f of findings) {
      console.log(`\n[${f.severity.toUpperCase()}] ${f.title} (${f.checkId}, confidence ${f.confidence})\n  ${f.url}`);
    }
    for (const e of errors) console.error(`Check ${e.checkId} failed: ${e.message}`);
    if (values.sarif !== undefined) {
      const sarifPath = resolve(values.sarif);
      await mkdir(dirname(sarifPath), { recursive: true });
      await writeFile(sarifPath, JSON.stringify(toSarif(findings.filter((f) => f.confidence !== 'low'), { version, target: target.href }), null, 2));
      console.log(`\nSARIF written to ${values.sarif}.`);
    }
    // Low-confidence findings are shown but never fail a run (PRD).
    if (values['write-baseline'] !== undefined) {
      const saved = run.findings.filter((f) => f.confidence !== 'low');
      await writeBaseline(values['write-baseline'], saved);
      console.log(`\nSaved ${saved.length} finding${saved.length === 1 ? '' : 's'} to ${values['write-baseline']} as accepted. Commit this file.`);
      return errors.length > 0 ? 1 : 0;
    }
    const failing = findings.filter((f) => f.confidence !== 'low' && meetsFailLevel(f.severity, failOn));
    if (recheck) {
      const id = recheckId!;
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
    await writeFile(join(dir, 'report.json'), JSON.stringify({ version, target: target.href, mode: activeMode ? `active-${intensity}` : 'passive', findings, errors, ...(activeMode ? { requests } : {}) }, null, 2));
    await writeFile(join(dir, 'report.md'), toMarkdown(target.href, findings, activeMode ? requests : undefined));
    await writeFile(join(dir, 'report.html'), toHtml(findings, { target: target.href, version, generatedAt: new Date(), requests: activeMode ? requests : undefined }));
    console.log(`\n${summary(findings)}. Report: ${join(outDir, 'report.html')}`);
    return failing.length > 0 || errors.length > 0 ? 1 : 0;
  } catch (err) {
    if (err instanceof ScopeError || err instanceof ActiveModeError) {
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
