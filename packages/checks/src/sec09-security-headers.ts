import { curlFor, type Check } from '@vibeprobe/core';

export const sec09: Check = {
  id: 'SEC-09',
  title: 'Security headers missing',
  severity: 'low',
  async run({ surface }) {
    const h = surface.home.headers;
    const https = new URL(surface.home.url).protocol === 'https:';
    const csp = h.get('content-security-policy');
    const missing: string[] = [];
    if (!csp) missing.push('Content-Security-Policy');
    if (!h.get('x-content-type-options')) missing.push('X-Content-Type-Options');
    if (!h.get('x-frame-options') && !/frame-ancestors/i.test(csp ?? '')) missing.push('X-Frame-Options (or CSP frame-ancestors)');
    if (!h.get('referrer-policy')) missing.push('Referrer-Policy');
    if (https && !h.get('strict-transport-security')) missing.push('Strict-Transport-Security');
    if (missing.length === 0) return [];
    return [
      {
        checkId: 'SEC-09',
        title: `${missing.length} browser security header${missing.length > 1 ? 's are' : ' is'} missing`,
        severity: 'low',
        confidence: 'high',
        url: surface.home.url,
        why: 'These headers tell the browser to block common attacks such as clickjacking and script injection. Without them the app relies on the browser defaults.',
        evidence: { request: `GET ${surface.home.url}`, status: surface.home.status, excerpt: `missing: ${missing.join(', ')}` },
        reproduce: curlFor(surface.home.url) + ' | head -20',
        fixPrompt:
          `This app does not send these security headers: ${missing.join(', ')}. Please add them for all responses in the framework's header configuration, ` +
          `with safe defaults: X-Content-Type-Options: nosniff, a frame-ancestors 'none' CSP directive (or X-Frame-Options: DENY), Referrer-Policy: strict-origin-when-cross-origin` +
          (https ? `, and Strict-Transport-Security: max-age=31536000; includeSubDomains` : '') +
          `. Start the Content-Security-Policy in report-only mode so nothing breaks.\n` +
          `Then run: npx vibeprobe ${surface.origin} --recheck SEC-09`,
      },
    ];
  },
};
