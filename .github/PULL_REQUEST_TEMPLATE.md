## What and why

<!-- One or two sentences. Link the issue: Closes #123 -->

## Checklist

- [ ] `npm test`, `npm run lint`, `npm run typecheck` pass
- [ ] New or changed check: planted hole added to `fixtures/vulnerable-app`, `fixtures/safe-app` still reports **zero** findings
- [ ] Requests only go through `ctx.client` and use `GET` / `HEAD` / `OPTIONS`
- [ ] Secrets are masked in evidence; no real secrets in fixtures (build fake ones at runtime)
- [ ] Docs / README / CHANGELOG updated if behavior changed
