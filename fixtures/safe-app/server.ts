// A well-behaved demo target: every vibeprobe check (passive and active) must report zero findings here.
// It answers 200 with HTML to unknown paths (like a single-page app), to prove checks do not trust a bare 200.
import { createServer, type IncomingMessage, type Server } from 'node:http';
import { fileURLToPath } from 'node:url';

const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
// A Supabase *anon* key is public by design and must not be reported.
const anonJwt = `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ role: 'anon', iss: 'supabase' })}.${'y'.repeat(24)}`;

const APP_JS = `const supabaseAnon = "${anonJwt}";
fetch("/api/products").then(r => r.json());
const links = ["/search?q=", "/greet?name=", "/api/items?id=", "/download?file=", "/api/fetch?url=", "/go?url="];
fetch("/api/login", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
fetch("/api/items", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
fetch("/api/profile", { method: "PUT", headers: { "content-type": "application/json" }, body: "{}" });
fetch("/api/settings", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
fetch("/api/merge", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
`;
const INDEX = '<!doctype html><title>safe</title><script src="/assets/app.js"></script><h1>Safe shop</h1><form action="/search"><input name="q"></form>';

const SECURITY_HEADERS = {
  'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
};

const LOGIN = '<!doctype html><title>Log in</title><h1>Log in</h1><form><input type="password" name="p"></form>';
const escapeHtml = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');

const readBody = (req: IncomingMessage) =>
  new Promise<string>((resolve) => {
    let data = '';
    req.on('data', (c) => (data += c));
    req.on('end', () => resolve(data));
  });

export function createApp(): Server {
  // Login attempts are counted per app instance: after 5 wrong tries the answer is 429.
  let loginAttempts = 0;
  return createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    const path = url.pathname;
    const method = req.method ?? 'GET';
    const send = (status: number, type: string, body: string, extra: Record<string, string> = {}) => {
      res.writeHead(status, { 'content-type': type, ...SECURITY_HEADERS, ...extra });
      res.end(body);
    };
    const json = (status: number, value: unknown, extra: Record<string, string> = {}) => send(status, 'application/json', JSON.stringify(value), extra);
    const body = method === 'POST' || method === 'PUT' || method === 'PATCH' ? await readBody(req) : '';

    // /admin is protected: anonymous users are sent to the login page (must not be reported).
    if (path === '/admin') {
      res.writeHead(302, { location: '/login', ...SECURITY_HEADERS });
      return res.end();
    }
    if (path === '/login') return send(200, 'text/html', LOGIN);
    if (path === '/assets/app.js') return send(200, 'text/javascript', APP_JS);
    if (path === '/api/products') return json(200, [{ id: 1, name: 'Mug' }]);

    // Everything below behaves the way the matching ACT check hopes to see.
    if (path === '/search') return send(200, 'text/html', `<!doctype html><title>Search</title><h1>Results for ${escapeHtml(url.searchParams.get('q') ?? '')}</h1>`);
    if (path === '/greet') return send(200, 'text/html', `<!doctype html><title>Hi</title><p>Hello ${escapeHtml(url.searchParams.get('name') ?? '')}</p>`);
    if (path === '/api/items') {
      if (method === 'POST') return json(401, { error: 'login required' });
      const id = url.searchParams.get('id');
      if (id !== null && !/^\d+$/.test(id)) return json(400, { error: 'invalid id' });
      return json(200, [{ id: 1, name: 'Mug' }]);
    }
    if (path === '/download') return send(404, 'text/plain', 'not found');
    if (path === '/api/fetch') return json(400, { error: 'host not allowed' });
    if (path === '/go') {
      const to = url.searchParams.get('url') ?? '';
      if (/^\/(?![/\\])/.test(to)) {
        res.writeHead(302, { location: to, ...SECURITY_HEADERS });
        return res.end();
      }
      return send(400, 'text/plain', 'only local paths');
    }
    if (path === '/api/login') {
      if (method !== 'POST') return json(405, { error: 'POST only' });
      loginAttempts++;
      if (loginAttempts > 5) return json(429, { error: 'too many attempts' }, { 'retry-after': '900' });
      let data: Record<string, unknown> = {};
      try {
        data = JSON.parse(body) as Record<string, unknown>;
      } catch {
        return json(400, { error: 'invalid json' });
      }
      if ((data.username !== undefined && typeof data.username !== 'string') || (data.email !== undefined && typeof data.email !== 'string') || typeof data.password !== 'string') {
        return json(400, { error: 'fields must be strings' });
      }
      return json(401, { error: 'wrong credentials' });
    }
    if (path === '/api/profile' || path === '/api/settings' || path === '/api/merge') {
      if (method === 'GET') return json(405, { error: 'not a read endpoint' });
      return json(401, { error: 'login required' });
    }

    // Safe cookies: the session cookie has its flags; the theme cookie is not a session, so it is not judged.
    res.writeHead(200, {
      'content-type': 'text/html',
      ...SECURITY_HEADERS,
      'set-cookie': ['sid=s3cr3tvalue; Path=/; HttpOnly; SameSite=Lax', 'theme=dark; Path=/'],
    });
    res.end(INDEX);
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT ?? 4011);
  createApp().listen(port, '127.0.0.1', () => console.log(`safe-app on http://localhost:${port}`));
}
