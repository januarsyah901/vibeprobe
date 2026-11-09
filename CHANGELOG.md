# Changelog

All notable changes are documented here. Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Scope lock: only `localhost`, `127.0.0.1`, `[::1]` and `*.localhost` by default.
- `GuardedHttpClient`: read-only methods, per-hop redirect checks, connect-time DNS validation against rebinding, token-bucket rate limit, backoff on 429/503, response size cap.
- Crawler: same-origin pages, scripts and endpoints; framework and dev-server detection.
- Check engine with per-check timeouts and isolated failures; zod-validated findings.
- Checks: SEC-01 (secrets in bundle), SEC-06 (sensitive files), SEC-08 (CORS), SEC-09 (security headers), SEC-11 (source maps).
- Vulnerable and safe fixture apps; every check is tested against both.
- CLI: scans a URL and writes `report.json` and `report.md`.
