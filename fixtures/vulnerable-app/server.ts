// WARNING: DELIBERATELY INSECURE. A demo target for vibeprobe. Never deploy or expose this.
// Every "secret" below is fake and assembled at runtime so secret scanners do not flag the repo.
import { createServer, type Server } from 'node:http';
import { fileURLToPath } from 'node:url';

const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
const fakeServiceRoleJwt = `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ role: 'service_role', iss: 'supabase' })}.${'x'.repeat(24)}`;
const fakeStripe = 'sk_' + 'live_' + 'A1b2C3d4E5f6G7h8I9j0K1l2';
const fakeAws = 'AKIA' + 'IOSFODNN7EXAMPLE';

const APP_JS = `
const stripe = "${fakeStripe}";
const aws = "${fakeAws}";
const supabaseAdmin = "${fakeServiceRoleJwt}";
fetch("/api/users").then(r => r.json());
//# ${"source" + "MappingURL"}=app.js.map
`;

export function createApp(): Server {
  return createServer((req, res) => {
    const path = (req.url ?? '/').split('?')[0];
    // SEC-08: reflects any origin and allows credentials.
    const origin = req.headers.origin;
    if (origin) {
      res.setHeader('access-control-allow-origin', origin);
      res.setHeader('access-control-allow-credentials', 'true');
    }
    const send = (status: number, type: string, body: string) => {
      res.writeHead(status, { 'content-type': type });
      res.end(body);
    };
    switch (path) {
      case '/':
        return send(200, 'text/html', '<!doctype html><title>demo</title><script src="/assets/app.js"></script><h1>Demo shop</h1>');
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
      default:
        return send(404, 'text/plain', 'not found');
    }
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT ?? 4010);
  createApp().listen(port, '127.0.0.1', () => console.log(`vulnerable-app on http://localhost:${port}`));
}
