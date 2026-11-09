import { parseArgs } from 'node:util';
import { GuardedHttpClient, Scope, ScopeError, VibeprobeError } from '@vibeprobe/core';
import { version } from '../package.json';

const HELP = `vibeprobe ${version}
Local security scanner for apps built with AI. Scans apps you own, read-only.

Usage
  npx vibeprobe <url>

Example
  npx vibeprobe http://localhost:3000

Options
  -h, --help      Show this help
  -v, --version   Show the version

Only localhost targets are allowed in this version.
Status: early preview. The scan checks land in v0.1.0; this release only checks that the target is reachable.`;

export async function main(argv: string[]): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        help: { type: 'boolean', short: 'h' },
        version: { type: 'boolean', short: 'v' },
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

  const client = new GuardedHttpClient({ scope: new Scope(), userAgent: `vibeprobe/${version}` });
  try {
    const res = await client.request(target);
    console.log(`Reached ${res.url} (HTTP ${res.status}).`);
    console.log('Security checks are not in this preview yet. Follow the project for v0.1.0.');
    return 0;
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
