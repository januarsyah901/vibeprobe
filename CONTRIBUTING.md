# Contributing to vibeprobe

Thanks for helping. vibeprobe is small on purpose, so a good contribution is often a few dozen lines.

## Easiest first contribution: a new check

A check is one file plus two fixtures. [docs/writing-a-check.md](docs/writing-a-check.md) walks through it. Look for issues labelled [`good first issue`](https://github.com/januarsyah901/vibeprobe/labels/good%20first%20issue) or [`new-check`](https://github.com/januarsyah901/vibeprobe/labels/new-check), or propose your own with the *Propose a new check* template.

Other useful contributions:

- **False positives** from real apps. Open a *False positive* issue. These are valuable: accuracy is the whole point.
- **Ways to break the scope guard.** Report them privately (see [SECURITY.md](SECURITY.md)), not as a public issue or PR.
- Docs, typos, better fix prompts for a specific framework.

## Ground rules

- **Accuracy over coverage.** A check ships with two fixtures: a vulnerable app where it must fire, and a safe app where it must stay silent.
- **Read-only.** Checks use `GET`, `HEAD` and `OPTIONS` through the `GuardedHttpClient` they are given. Never import a network module directly; lint stops you.
- **No live targets in tests.** Tests run against local fixtures only.
- **Mask secrets** in anything that reaches a report. Fake secrets in fixtures are built at runtime so secret scanners stay quiet.
- **Plain language.** Findings are for people without a security background: no jargon, two sentences for *why*.

## Setup

Requires Node.js 22.18+.

```bash
git clone https://github.com/januarsyah901/vibeprobe.git
cd vibeprobe
npm install
npm test            # vitest
npm run typecheck
npm run lint
npm run build
```

## Pull requests

1. Fork, branch from `main`, keep the change focused.
2. Make sure `npm test`, `npm run lint` and `npm run typecheck` pass. CI runs them on Node 22 and 24.
3. Fill in the PR template. Update `CHANGELOG.md` under *Unreleased* for user-visible changes.

By contributing you agree your work is released under the [MIT License](LICENSE) and that you will follow the [Code of Conduct](CODE_OF_CONDUCT.md).
