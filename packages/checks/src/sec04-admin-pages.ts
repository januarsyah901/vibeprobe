import { curlFor, type Check } from '@vibeprobe/core';

const PATHS = ['/admin', '/dashboard', '/admin/dashboard', '/administrator'];
const ADMIN_MARKER = /<(?:title|h1)[^>]*>[^<]*\b(admin|administrator|dashboard)\b/i;
const LOGIN_MARKER = /type\s*=\s*["']password["']|\b(?:log\s?in|sign\s?in)\b/i;
const DATA_MARKER = /<table\b|<tbody\b/i;

export const sec04: Check = {
  id: 'SEC-04',
  title: 'Admin page without protection',
  severity: 'high',
  async run({ client, surface }) {
    // Single-page apps answer 200 with the same shell for everything: compare against known fallbacks.
    const random = new URL(`/vibeprobe-404-${Math.random().toString(36).slice(2, 10)}`, surface.origin).href;
    const fallback = (await client.request(random)).body;
    const shells = new Set([surface.home.body, fallback]);

    for (const path of PATHS) {
      const url = new URL(path, surface.origin).href;
      const res = await client.request(url);
      const type = res.headers.get('content-type') ?? '';
      if (res.status !== 200 || !type.includes('text/html')) continue;
      if (shells.has(res.body)) continue; // the SPA shell, not a real page
      if (res.redirects.length > 0 && /log-?in|sign-?in|auth/i.test(res.url)) continue; // sent to a login page
      if (LOGIN_MARKER.test(res.body)) continue; // the page is a login form
      if (!ADMIN_MARKER.test(res.body)) continue;
      const hasData = DATA_MARKER.test(res.body);
      return [
        {
          checkId: 'SEC-04',
          title: `${path} opens without logging in`,
          severity: 'high',
          confidence: hasData ? 'high' : 'medium',
          url,
          why: 'An admin or dashboard page answered a request that had no login. Anyone who guesses the address can view it, and may be able to change things.',
          evidence: {
            request: `GET ${url} (no cookies)`,
            status: 200,
            excerpt: (ADMIN_MARKER.exec(res.body)?.[0] ?? '').replace(/\s+/g, ' ').slice(0, 120) + (hasData ? ' [contains a data table]' : ''),
          },
          reproduce: curlFor(url) + ' | head -20',
          fixPrompt:
            `The page ${path} is reachable without a login. Please:\n` +
            `1. Protect every admin route on the server (middleware that checks the session and the user's admin role), not only by hiding links in the UI.\n` +
            `2. Redirect anonymous users to the login page, and return 403 for logged-in users who are not admins.\n` +
            `3. Check that the API endpoints used by this page enforce the same rule.\n` +
            `Then run: npx vibeprobe ${surface.origin} --recheck SEC-04`,
        },
      ];
    }
    return [];
  },
};
