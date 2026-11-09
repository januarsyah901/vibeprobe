# Contributing to vibeprobe

Thanks for helping. The most useful contributions right now:

1. **New checks** for holes that AI-built apps commonly ship with (each check will be a small self-contained plugin once the check engine lands in v0.1.0).
2. **Ways to break the scope guard.** If you find one, report it privately (see [SECURITY.md](SECURITY.md)) rather than opening a PR.
3. **False positives** you hit on real apps. Open an issue with what was reported and why it is wrong.

## Ground rules

- **Accuracy over coverage.** A check must ship with two fixtures: a vulnerable app where it must fire, and a safe app where it must stay silent.
- **Read-only.** Checks may only use `GET`, `HEAD` and `OPTIONS` through the `GuardedHttpClient` they are given. Never import a network module directly; lint will stop you.
- **No live targets in tests.** Tests run against local fixtures only.

## Setup

```bash
npm install
npm test
npm run typecheck
npm run lint
```

Open a pull request against `main`. CI runs lint, typecheck, tests and the build on Node 22 and 24.
