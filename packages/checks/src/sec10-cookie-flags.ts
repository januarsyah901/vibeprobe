import { maskSecret, type Check, type Finding } from '@vibeprobe/core';

const SESSION_NAME = /(sess|sid$|^sid|token|auth|jwt|login|connect\.sid)/i;

interface ParsedCookie {
  name: string;
  value: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: boolean;
}

export function parseSetCookie(header: string): ParsedCookie {
  const [pair = '', ...attrs] = header.split(';').map((p) => p.trim());
  const eq = pair.indexOf('=');
  const flags = attrs.map((a) => a.toLowerCase());
  return {
    name: eq === -1 ? pair : pair.slice(0, eq),
    value: eq === -1 ? '' : pair.slice(eq + 1),
    secure: flags.includes('secure'),
    httpOnly: flags.includes('httponly'),
    sameSite: flags.some((a) => a.startsWith('samesite=')),
  };
}

export const sec10: Check = {
  id: 'SEC-10',
  title: 'Session cookie without safe flags',
  severity: 'medium',
  async run({ client, surface }) {
    const https = new URL(surface.origin).protocol === 'https:';
    const seen = new Map<string, { cookie: ParsedCookie; url: string }>();
    const record = (headers: Headers, url: string) => {
      for (const raw of headers.getSetCookie()) {
        const cookie = parseSetCookie(raw);
        if (SESSION_NAME.test(cookie.name) && !seen.has(cookie.name)) seen.set(cookie.name, { cookie, url });
      }
    };
    record(surface.home.headers, surface.home.url);
    for (const page of surface.pages.slice(0, 5)) {
      if (page === surface.home.url) continue;
      record((await client.request(page)).headers, page);
    }

    const findings: Finding[] = [];
    for (const { cookie, url } of seen.values()) {
      const missing: string[] = [];
      if (!cookie.httpOnly) missing.push('HttpOnly');
      if (!cookie.sameSite) missing.push('SameSite');
      // Secure only means something over https; plain-http localhost cannot set it meaningfully.
      if (https && !cookie.secure) missing.push('Secure');
      if (missing.length === 0) continue;
      findings.push({
        checkId: 'SEC-10',
        title: `The "${cookie.name}" cookie is missing ${missing.join(', ')}`,
        severity: 'medium',
        confidence: 'high',
        url,
        why: 'Without these flags, a script injected into your page can steal the login cookie, or another site can make the browser send it along. That lets someone take over a logged-in session.',
        evidence: {
          request: `GET ${url}`,
          status: 200,
          excerpt: `Set-Cookie: ${cookie.name}=${maskSecret(cookie.value, 2)}; (missing: ${missing.join(', ')})`,
        },
        reproduce: `curl -sS -i '${url}' | grep -i '^set-cookie'`,
        fixPrompt:
          `The session cookie "${cookie.name}" is sent without: ${missing.join(', ')}. Please set it with HttpOnly, SameSite=Lax (or Strict)` +
          `${https ? ', and Secure' : ''} in the auth/session configuration (for example the cookie options of the session library or framework). ` +
          `Do not store the session token in localStorage instead.\n` +
          `Then run: npx vibeprobe ${surface.origin} --recheck SEC-10`,
      });
    }
    return findings;
  },
};
