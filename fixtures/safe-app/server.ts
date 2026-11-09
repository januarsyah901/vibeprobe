// A well-behaved demo target: every vibeprobe check must report zero findings here.
// It answers 200 with HTML to unknown paths (like a single-page app), to prove checks do not trust a bare 200.
import { createServer, type Server } from 'node:http';
import { fileURLToPath } from 'node:url';

const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
// A Supabase *anon* key is public by design and must not be reported.
const anonJwt = `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ role: 'anon', iss: 'supabase' })}.${'y'.repeat(24)}`;

const APP_JS = `const supabaseAnon = "${anonJwt}";\nfetch("/api/products").then(r => r.json());\n`;
const INDEX = '<!doctype html><title>safe</title><script src="/assets/app.js"></script><h1>Safe shop</h1>';

const SECURITY_HEADERS = {
  'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
};

export function createApp(): Server {
  return createServer((req, res) => {
    const path = (req.url ?? '/').split('?')[0];
    if (path === '/assets/app.js') {
      res.writeHead(200, { 'content-type': 'text/javascript', ...SECURITY_HEADERS });
      return res.end(APP_JS);
    }
    if (path === '/api/products') {
      res.writeHead(200, { 'content-type': 'application/json', ...SECURITY_HEADERS });
      return res.end('[{"id":1,"name":"Mug"}]');
    }
    res.writeHead(200, { 'content-type': 'text/html', ...SECURITY_HEADERS });
    res.end(INDEX);
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT ?? 4011);
  createApp().listen(port, '127.0.0.1', () => console.log(`safe-app on http://localhost:${port}`));
}
