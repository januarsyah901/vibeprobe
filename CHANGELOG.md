# Changelog

All notable changes are documented here. Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [Unreleased]

### Added
- **Active mode** (`--active [light|full]`, localhost only): ACT-01 reflected XSS, ACT-02 SQL injection (error-based), ACT-03 CSRF, ACT-04 path traversal, ACT-05 login attempt limit, ACT-06 write endpoints without login, ACT-07 mass assignment, ACT-08 NoSQL injection, ACT-09 template injection, ACT-10 SSRF (canary listener on 127.0.0.1), ACT-11 Host header injection, ACT-12 hidden routes, ACT-13 prototype pollution.
- Active-mode guardrails: explicit confirmation (`--yes` in CI), no `DELETE` ever, writes never retried, request budget (1,500), writes refused for any non-local host, `--plan` dry run, and an audit trail of every request in the reports.
- Passive checks: SEC-12 (API docs, GraphQL introspection), SEC-13 (secrets returned by API endpoints), SEC-14 (JWT analysis), SEC-15 (open redirect).
- SEC-06 now also covers database dumps, `.npmrc`, AWS credentials, `/actuator/env`, `/metrics`, `phpinfo`, `server-status`, `.DS_Store` and directory listings.
- `--sarif <file>` writes SARIF 2.1.0 for the GitHub Security tab; the Action gets `sarif` and `active` inputs.
- The crawler now also records forms, query parameters and endpoints called with POST, PUT or PATCH.
- `--recheck ACT-nn` (with `--active`).

### Changed
- `GuardedHttpClient` accepts a request body and `followRedirects: false`, records a request history, and can enforce a request budget. Write methods need an `ActiveConsent`, which only `grantActiveConsent()` can create, and only for localhost.

## [0.1.0] - 2026-11-09

First public release.

### Added
- CI mode: `--fail-on <level>`, `--baseline <file>`, `--write-baseline <file>`, `--out <dir>`, `--rate <n>`.
- GitHub Action (`action.yml`) with report upload; CI job that runs the built CLI against both fixtures.
- Self-contained `report.html`: no external requests, light and dark, "Fix these first", copy button per fix prompt; everything from the target is HTML-escaped.

### Added
- Scope lock: only `localhost`, `127.0.0.1`, `[::1]` and `*.localhost` by default.
- `GuardedHttpClient`: read-only methods, per-hop redirect checks, connect-time DNS validation against rebinding, token-bucket rate limit, backoff on 429/503, response size cap.
- Crawler: same-origin pages, scripts and endpoints; framework and dev-server detection.
- Check engine with per-check timeouts and isolated failures; zod-validated findings.
- Checks: SEC-01 (secrets in bundle), SEC-03 (unauthenticated API), SEC-04 (admin pages), SEC-06 (sensitive files), SEC-07 (debug mode), SEC-08 (CORS), SEC-09 (security headers), SEC-10 (cookie flags), SEC-11 (source maps).
- `--recheck <ID>` runs a single check to confirm a fix.
- Low-confidence findings are reported separately and never fail a run.
- Vulnerable and safe fixture apps; every check is tested against both.
- CLI: scans a URL and writes `report.json` and `report.md`.
