// WARNING: DELIBERATELY INSECURE. A demo target for vibeprobe. Never deploy or expose this.
// Every "secret" below is fake and assembled at runtime so secret scanners do not flag the repo.
import { createServer, type IncomingMessage, type Server } from 'node:http';
import { fileURLToPath } from 'node:url';

const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
const fakeServiceRoleJwt = `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ role: 'service_role', iss: 'supabase' })}.${'x'.repeat(24)}`;
// An admin token with no expiry that the API hands to anyone (SEC-14).
const fakeAdminJwt = `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ sub: '1', role: 'admin' })}.${'z'.repeat(24)}`;
const fakeStripe = 'sk_' + 'live_' + 'A1b2C3d4E5f6G7h8I9j0K1l2';
const fakeAws = 'AKIA' + 'IOSFODNN7EXAMPLE';

const APP_JS = `
const stripe = "${fakeStripe}";
const aws = "${fakeAws}";
const supabaseAdmin = "${fakeServiceRoleJwt}";
fetch("/api/users").then(r => r.json());
fetch("/api/orders").then(r => r.json());
fetch("/api/config").then(r => r.json());
const links = ["/search?q=", "/greet?name=", "/api/items?id=", "/download?file=", "/api/fetch?url=", "/go?url="];
fetch("/api/login", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
fetch("/api/items", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
fetch("/api/profile", { method: "PUT", headers: { "content-type": "application/json" }, body: "{}" });
fetch("/api/settings", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
fetch("/api/merge", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
//# ${"source" + "MappingURL"}=app.js.map
`;

// ACT-13: a naive deep merge. It runs on a throwaway prototype so the real Object.prototype is never touched.
function SandboxCtor() {}
const sandboxProto: Record<string, unknown> = { constructor: SandboxCtor };
(SandboxCtor as unknown as { prototype: object }).prototype = sandboxProto;
function naiveMerge(target: Record<string, any>, src: Record<string, any>) {
  for (const key of Object.keys(src)) {
    if (src[key] !== null && typeof src[key] === 'object') naiveMerge((target[key] ??= {}), src[key]);
    else target[key] = src[key];
  }
}

// ACT-09: a toy "template engine" that evaluates a*b. No real code is ever executed.
function renderTemplate(input: string): string {
  return input
    .replace(/\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}/g, (_, a, b) => String(Number(a) * Number(b)))
    .replace(/\$\{\s*(\d+)\s*\*\s*(\d+)\s*\}/g, (_, a, b) => String(Number(a) * Number(b)))
    .replace(/<%=\s*(\d+)\s*\*\s*(\d+)\s*%>/g, (_, a, b) => String(Number(a) * Number(b)))
    .replace(/#\{\s*(\d+)\s*\*\s*(\d+)\s*\}/g, (_, a, b) => String(Number(a) * Number(b)));
}

const readBody = (req: IncomingMessage) =>
  new Promise<string>((resolve) => {
    let data = '';
    req.on('data', (c) => (data += c));
    req.on('end', () => resolve(data));
  });
const parse = (s: string): Record<string, any> => {
  try {
    const v = JSON.parse(s);
    return v !== null && typeof v === 'object' ? v : {};
  } catch {
    return Object.fromEntries(new URLSearchParams(s));
  }
};

export function createApp(): Server {
  return createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    const path = url.pathname;
    const method = req.method ?? 'GET';
    // SEC-08: reflects any origin and allows credentials.
    const origin = req.headers.origin;
    if (origin) {
      res.setHeader('access-control-allow-origin', origin);
      res.setHeader('access-control-allow-credentials', 'true');
    }
    const send = (status: number, type: string, body: string, extra: Record<string, string> = {}) => {
      res.writeHead(status, { 'content-type': type, ...extra });
      res.end(body);
    };
    const json = (status: number, value: unknown) => send(status, 'application/json', JSON.stringify(value));
    const body = method === 'POST' || method === 'PUT' || method === 'PATCH' ? await readBody(req) : '';

    switch (path) {
      case '/':
        // SEC-10: a session cookie with no HttpOnly / SameSite.
        return send(
          200,
          'text/html',
          '<!doctype html><title>demo</title><script src="/assets/app.js"></script><h1>Demo shop</h1><form action="/search"><input name="q"></form>',
          { 'set-cookie': 'session=abc123def456; Path=/' },
        );
      case '/admin':
        // SEC-04: an admin page with a data table and no login.
        return send(200, 'text/html', '<!doctype html><title>Admin Dashboard</title><h1>Admin panel</h1><table><tr><td>a@example.com</td></tr></table>');
      case '/api/orders':
        // SEC-03 (low confidence): sounds private, but holds no personal fields.
        return send(200, 'application/json', '[{"id":7,"total":19}]');
      case '/assets/app.js':
        return send(200, 'text/javascript', APP_JS);
      case '/assets/app.js.map':
        return send(200, 'application/json', JSON.stringify({ version: 3, sources: ['src/App.tsx'], mappings: 'AAAA' }));
      case '/api/users':
        return send(200, 'application/json', '[{"id":1,"email":"a@example.com"}]');
      case '/.env':
        return send(200, 'text/plain', 'DATABASE_URL=postgres://user:hunter2@db/app\nSTRIPE_SECRET=' + fakeStripe + '\n');
      case '/.git/HEAD':
        return send(200, 'text/plain', 'ref: refs/heads/main\n');
      case '/.git/config':
        return send(200, 'text/plain', '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://token123@github.com/demo/shop.git\n');

      // ---- passive: SEC-06+, SEC-12, SEC-13, SEC-14, SEC-15 ----
      case '/backup.sql':
        return send(200, 'application/sql', "-- MySQL dump 10.13\nCREATE TABLE users (email text, pw text);\nINSERT INTO users VALUES ('a@example.com','hunter2');\n");
      case '/actuator/env':
        return json(200, { propertySources: [{ name: 'systemEnvironment', properties: {} }] });
      case '/metrics':
        return send(200, 'text/plain', '# HELP http_requests_total The total number of requests.\n# TYPE http_requests_total counter\nhttp_requests_total 12\n');
      case '/uploads/':
        return send(200, 'text/html', '<html><head><title>Index of /uploads/</title></head><body><h1>Index of /uploads/</h1><a href="a.png">a.png</a></body></html>');
      case '/openapi.json':
        return json(200, { openapi: '3.0.0', info: { title: 'demo' }, paths: { '/api/users': {}, '/api/orders': {} } });
      case '/graphql':
        if (decodeURIComponent(url.search).includes('__schema')) return json(200, { data: { __schema: { types: [{ name: 'User' }, { name: 'Order' }] } } });
        return json(400, { errors: [{ message: 'no query' }] });
      case '/api/config':
        // SEC-13 (a secret in the answer) and SEC-14 (a public admin token that never expires).
        return json(200, { env: 'production', stripeKey: fakeStripe, sessionToken: fakeAdminJwt });
      case '/go': {
        // SEC-15: redirects wherever it is told.
        const to = url.searchParams.get('url');
        if (!to) return send(400, 'text/plain', 'missing url');
        res.writeHead(302, { location: to });
        return res.end();
      }

      // ---- active: ACT-01 to ACT-13 ----
      case '/search':
        // ACT-01: the query is printed back as raw HTML.
        return send(200, 'text/html', `<!doctype html><title>Search</title><h1>Results for ${url.searchParams.get('q') ?? ''}</h1>`);
      case '/greet':
        // ACT-09: the name is run through the "template engine".
        return send(200, 'text/html', `<!doctype html><title>Hi</title><p>Hello ${renderTemplate(url.searchParams.get('name') ?? '')}</p>`);
      case '/api/items': {
        if (method === 'POST') {
          // ACT-06: validation runs before any login check, and there is no login check.
          const data = parse(body);
          if (!data.name) return json(400, { error: 'name is required' });
          return json(201, { id: 99, name: data.name });
        }
        // ACT-02: the id goes straight into a query; a quote breaks it.
        const id = url.searchParams.get('id');
        if (id !== null && id.includes("'")) {
          return json(500, { error: `SQLITE_ERROR: unrecognized token: "'${id}'"` });
        }
        return json(200, [{ id: 1, name: 'Mug' }]);
      }
      case '/download': {
        // ACT-04: a pretend file system where "../" escapes into the system files.
        const file = url.searchParams.get('file') ?? '';
        if (file.includes('etc/passwd')) return send(200, 'text/plain', 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n');
        if (file.toLowerCase().includes('win.ini')) return send(200, 'text/plain', '[fonts]\n[extensions]\n');
        return send(404, 'text/plain', 'not found');
      }
      case '/api/fetch': {
        // ACT-10: fetches whatever address it is given.
        const target = url.searchParams.get('url') ?? '';
        try {
          await fetch(target);
        } catch {
          /* the demo does not care */
        }
        return json(200, { fetched: true });
      }
      case '/api/login': {
        // ACT-05 (no attempt limit) and ACT-08 (an object as the password matches).
        if (method !== 'POST') return json(405, { error: 'POST only' });
        const data = parse(body);
        const password = data.password;
        if (password !== null && typeof password === 'object') return json(200, { token: 'session-for-first-user' });
        if ((data.username === 'admin' || data.email === 'admin@example.com') && password === 'correct horse') return json(200, { token: 'session-for-admin' });
        return json(401, { error: 'wrong credentials' });
      }
      case '/api/profile': {
        // ACT-07: every field of the body is copied into the record, including role.
        if (method !== 'PUT' && method !== 'POST' && method !== 'PATCH') return json(405, { error: 'PUT only' });
        return json(200, { id: 1, name: 'demo', ...parse(body) });
      }
      case '/api/settings':
        // ACT-03: accepts a cross-site form post: no token, no origin check.
        if (method !== 'POST') return json(405, { error: 'POST only' });
        return json(200, { ok: true });
      case '/api/merge': {
        // ACT-13: deep-merges the body into a shared object.
        if (method !== 'POST') return json(405, { error: 'POST only' });
        let incoming: Record<string, any> = {};
        try {
          incoming = JSON.parse(body) as Record<string, any>;
        } catch {
          /* ignore */
        }
        naiveMerge(Object.create(sandboxProto), incoming);
        const probe = Object.create(sandboxProto) as Record<string, unknown>;
        return json(200, { ok: true, vpPolluted: probe.vpPolluted ?? null });
      }
      case '/api/v1/admin':
        // ACT-12: not linked anywhere, answers anyone.
        return json(200, [{ id: 1, email: 'root@example.com', role: 'admin' }]);
      case '/reset': {
        // ACT-11: builds the reset link from the Host header.
        const host = req.headers['x-forwarded-host'] ?? req.headers.host;
        return send(200, 'text/html', `<!doctype html><title>Reset</title><p><a href="http://${host}/reset?token=abc123">Reset your password</a></p>`);
      }
      default:
        // SEC-07: unknown paths print a stack trace.
        return send(
          500,
          'text/html',
          '<pre>Error: ENOENT: no such file or directory\n    at Object.openSync (node:fs:573:18)\n    at handle (/srv/app/server.js:41:11)\n    at Layer.handle (/srv/app/node_modules/express/lib/router/layer.js:95:5)</pre>',
        );
    }
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT ?? 4010);
  createApp().listen(port, '127.0.0.1', () => console.log(`vulnerable-app on http://localhost:${port}`));
}
