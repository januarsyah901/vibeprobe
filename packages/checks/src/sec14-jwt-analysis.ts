import { curlFor, maskSecret, type Check, type Finding } from '@vibeprobe/core';
import { JWT_RE, parseJwt } from './secret-patterns';

const ADMIN_ROLE = /^(admin|administrator|superuser|root|owner)$/i;

interface Source {
  url: string;
  where: string;
  text: string;
}

/**
 * Reads login tokens (JWTs) the app already hands out and looks for the three classic mistakes:
 * no signature, an admin token that anyone can fetch, and a token that never expires.
 * It only reads. It never tries to forge or replay a token.
 */
export const sec14: Check = {
  id: 'SEC-14',
  title: 'Weak or exposed login token',
  severity: 'high',
  async run({ client, surface }) {
    const sources: Source[] = [];
    for (const s of surface.scripts) sources.push({ url: s.url, where: 'the JavaScript bundle', text: s.body });
    sources.push({ url: surface.home.url, where: 'the home page', text: surface.home.body });
    for (const raw of surface.home.headers.getSetCookie()) sources.push({ url: surface.home.url, where: 'a cookie', text: raw });
    for (const url of surface.endpoints.slice(0, 25)) {
      const res = await client.request(url);
      if (res.status !== 200 || (res.headers.get('content-type') ?? '').includes('html')) continue;
      sources.push({ url, where: 'an endpoint that needs no login', text: res.body });
      for (const raw of res.headers.getSetCookie()) sources.push({ url, where: 'a cookie', text: raw });
    }

    const findings: Finding[] = [];
    const seen = new Set<string>();
    for (const src of sources) {
      for (const m of src.text.matchAll(JWT_RE)) {
        const token = m[0];
        if (seen.has(token)) continue;
        seen.add(token);
        const jwt = parseJwt(token);
        if (!jwt) continue;
        // Supabase anon keys are public by design (service_role is SEC-01's job).
        if (jwt.payload.role === 'anon' || jwt.payload.role === 'service_role') continue;

        const issues: string[] = [];
        const alg = String(jwt.header.alg ?? '').toLowerCase();
        if (alg === 'none') issues.push('uses alg "none": it has no signature, so anyone can write their own');
        const role = jwt.payload.role;
        if ((typeof role === 'string' && ADMIN_ROLE.test(role)) || jwt.payload.isAdmin === true || jwt.payload.admin === true) {
          issues.push('grants admin rights and was handed out without any login');
        }
        if (jwt.payload.exp === undefined) issues.push('has no expiry ("exp"), so it works forever once stolen');
        if (issues.length === 0) continue;

        const worst = issues[0]!.startsWith('uses alg') ? 'unsigned' : issues[0]!.startsWith('grants') ? 'admin' : 'forever';
        const title =
          worst === 'unsigned'
            ? 'A login token has no signature (alg none)'
            : worst === 'admin'
              ? 'An admin login token is public'
              : 'A login token never expires';
        findings.push({
          checkId: 'SEC-14',
          title,
          severity: worst === 'forever' ? 'medium' : 'high',
          confidence: worst === 'forever' ? 'medium' : 'high',
          url: src.url,
          why:
            worst === 'unsigned'
              ? 'A token without a signature proves nothing. If the server accepts it, anyone can log in as anyone.'
              : worst === 'admin'
                ? 'Anyone who loads the app can copy this token and act as an administrator.'
                : 'A token that never expires keeps working after logout, after a password change, and in the hands of a thief.',
          evidence: { request: `GET ${src.url}`, status: 200, excerpt: `token ${maskSecret(token)} found in ${src.where}; it ${issues.join('; and ')}` },
          reproduce: curlFor(src.url) + ` | grep -o 'eyJ[A-Za-z0-9_.-]*'`,
          fixPrompt:
            `A login token (JWT) in this app ${issues.join('; and ')}. Please:\n` +
            `1. Sign every token with a strong secret or key (HS256 with a long random secret, or RS256), and reject alg "none" when verifying.\n` +
            `2. Never ship an admin or long-lived token in the browser bundle or in a response to anonymous callers.\n` +
            `3. Give tokens a short "exp" (for example 15 minutes to 1 hour) and refresh them.\n` +
            `4. Treat the exposed token as stolen: invalidate it and rotate the signing secret.\n` +
            `Then run: npx vibeprobe ${surface.origin} --recheck SEC-14`,
        });
      }
    }
    return findings;
  },
};
