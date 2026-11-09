# vibeprobe

**A local, read-only security scanner for apps built with AI.**
Point it at the app running on your laptop. It finds the holes AI-written apps tend to ship with, explains them in plain language, and gives you a fix prompt to paste into Cursor, Claude Code, Lovable or Bolt.

```bash
npx vibeprobe http://localhost:3000
```

> **Status: early preview (0.0.x), not on npm yet.** Working today: the safety core (scope lock, DNS-rebinding protection, read-only requests, rate limiting), a crawler, and 5 checks (SEC-01, 06, 08, 09, 11) with Markdown and JSON reports. Every check is tested against a deliberately vulnerable app (must find the hole) and a safe app (must stay silent). Coming for v0.1.0: SEC-02, 03, 04, 07, 10, an HTML report, and the `--recheck` flag. Watch or star the repo to follow along.

## Why

Most security tooling for AI-built apps reads your code. vibeprobe tests the **running app**, the way an attacker would, but only read-only and only against apps you own.

Tools like OWASP ZAP and Nuclei are powerful but built for security people. vibeprobe is built for the person who just shipped a feature with an AI assistant and wants to know: *is this safe to share?*

## Checks

| ID | Check | Severity | Status |
| --- | --- | --- | --- |
| SEC-01 | Secrets in the JavaScript bundle (e.g. a Supabase `service_role` key) | Critical | done |
| SEC-02 | Open database: Supabase tables without RLS, open Firebase rules | Critical | planned |
| SEC-03 | API endpoints that answer without authentication | High | planned |
| SEC-04 | Admin pages without protection | High | planned |
| SEC-06 | Exposed `.env`, `.git/` and backup files | Critical | done |
| SEC-07 | Debug mode and stack traces in production | Medium | planned |
| SEC-08 | CORS that reflects any origin with credentials | High | done |
| SEC-09 | Missing security headers | Low | done |
| SEC-10 | Session cookies without `Secure` / `HttpOnly` / `SameSite` | Medium | planned |
| SEC-11 | Source maps exposed in production | Medium | done |

Planned next: IDOR with two test accounts (SEC-05), CI mode with a baseline, SARIF output.

Every finding comes with evidence, a confidence level, a read-only `curl` to reproduce it, and a fix prompt.

## Safety rules (enforced in code, not just written here)

- **Your apps only.** By default vibeprobe only talks to `localhost`, `127.0.0.1`, `[::1]` and `*.localhost`. Public domains will need proof of ownership (a token file or DNS TXT record).
- **No escaping the scope.** Every redirect hop is re-checked, and hostnames are resolved and checked at connect time, so DNS rebinding cannot point it somewhere else.
- **Read-only.** Only `GET`, `HEAD` and `OPTIONS` are sent. Other methods are blocked inside the HTTP client.
- **Gentle.** 5 requests per second by default, with backoff on `429` / `503`.
- **100% local.** No telemetry. Nothing is sent anywhere except your own app. Secrets in reports are masked.

All network access goes through one class, `GuardedHttpClient`, and a lint rule forbids network calls anywhere else.

**Do not use vibeprobe against systems you do not own or have written permission to test.**

## Development

Requires Node.js 22.18+.

```bash
npm install
npm test          # vitest
npm run typecheck
npm run lint
npm run build     # builds packages/cli/dist
node packages/cli/dist/bin.js http://localhost:3000
```

```
packages/
  core/     # scope guard, guarded HTTP client, rate limiter, crawler, check runner, finding schema
  checks/   # one file per check
  cli/      # the `vibeprobe` npm package
fixtures/   # deliberately vulnerable app and a safe app (see fixtures/README.md)
```

See [CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability in vibeprobe itself, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
