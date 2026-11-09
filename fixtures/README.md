# Fixtures

> **WARNING: `vulnerable-app/` is deliberately insecure. Never deploy it or expose it to a network.** It only listens on 127.0.0.1.

- `vulnerable-app/`: every check must find its planted hole here. All secrets in it are fake and built at runtime.
- `safe-app/`: every check must report zero findings here. It answers `200` with HTML to unknown paths on purpose, to prove checks do not treat a bare `200` as proof.

Run them (Node 22.18+):

```bash
node fixtures/vulnerable-app/server.ts   # http://localhost:4010
node fixtures/safe-app/server.ts         # http://localhost:4011
node packages/cli/dist/bin.js http://localhost:4010
```
