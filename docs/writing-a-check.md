# Writing a check

A check is one small file plus two fixtures. If you can write a `fetch`-style request and a regex, you can write one.

## 1. The interface

```ts
import type { Check } from '@vibeprobe/core';

export interface Check {
  id: string;                 // 'SEC-12'
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  run(ctx: CheckContext): Promise<Finding[]>;
}
// ctx.client   GuardedHttpClient: the only way to make requests (GET/HEAD/OPTIONS)
// ctx.surface  pages, scripts (with bodies), endpoints, framework, isDevServer
// ctx.target   the URL the user asked for
```

## 2. Write it

Create `packages/checks/src/sec12-my-check.ts`:

```ts
import { curlFor, type Check } from '@vibeprobe/core';

export const sec12: Check = {
  id: 'SEC-12',
  title: 'Example',
  severity: 'medium',
  async run({ client, surface }) {
    const url = new URL('/some/path', surface.origin).href;
    const res = await client.request(url);
    // A bare 200 proves nothing: single-page apps answer 200 to everything.
    // Match something specific to the problem.
    if (res.status !== 200 || !/specific-signature/.test(res.body)) return [];
    return [{
      checkId: 'SEC-12',
      title: 'Plain-language title',
      severity: 'medium',
      confidence: 'high',        // 'high' only with direct proof
      url,
      why: 'At most two sentences, no jargon.',
      evidence: { request: `GET ${url}`, status: res.status, excerpt: '...masked...' },
      reproduce: curlFor(url),
      fixPrompt: 'A prompt the user can paste into an AI coding tool as-is.',
    }];
  },
};
```

Register it in `packages/checks/src/index.ts`.

## 3. Rules

- **Read-only.** Only `GET`, `HEAD`, `OPTIONS`, only through `ctx.client`. Do not import `fetch`, `undici` or `node:http`; lint will stop you.
- **Mask secrets.** Use `maskSecret` / `maskEnvLines` before putting anything in `evidence`.
- **High confidence needs proof.** A signature match on the response body, not just a status code.
- **Two fixtures.** Add the planted hole to `fixtures/vulnerable-app/server.ts` and make sure `fixtures/safe-app/server.ts` stays clean. Fake secrets must be built at runtime (string concatenation) so secret scanners do not flag the repo.
- **Test it.** Add a row to the table in `packages/checks/test/fixtures.test.ts`.

## 4. Run

```bash
npm test && npm run lint && npm run typecheck
```
