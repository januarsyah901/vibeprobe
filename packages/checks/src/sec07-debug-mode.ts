import { curlFor, type Check } from '@vibeprobe/core';

interface Signature {
  re: RegExp;
  /** A stack trace is direct proof; a debug banner is a strong hint. */
  confidence: 'high' | 'medium';
}

const SIGNATURES: Signature[] = [
  { re: /\bat\s+[^\n(]{1,80}\s\((?:\/|[A-Za-z]:\\|file:|node:)[^)\n]*:\d+:\d+\)/, confidence: 'high' }, // Node
  { re: /(?:&nbsp;){2,}at\s+\S+.*:\d+:\d+/, confidence: 'high' }, // Express dev error page
  { re: /Traceback \(most recent call last\)/, confidence: 'high' }, // Python
  { re: /\bat\s+[\w.$]+\([\w$]+\.java:\d+\)/, confidence: 'high' }, // Java
  { re: /#\d+\s+\/[^\s]+\.php\(\d+\)/, confidence: 'high' }, // PHP
  { re: /Django Debug|You're seeing this error because you have DEBUG = True|Werkzeug Debugger|Whoops!|Laravel.{0,40}Ignition/i, confidence: 'medium' },
];

export const sec07: Check = {
  id: 'SEC-07',
  title: 'Debug mode or stack trace exposed',
  severity: 'medium',
  async run({ client, surface }) {
    // A dev server shows these on purpose. Only a non-dev target makes this a finding.
    if (surface.isDevServer) return [];
    const probe = new URL(`/vibeprobe-404-${Math.random().toString(36).slice(2, 10)}`, surface.origin).href;
    const res = await client.request(probe);
    for (const sig of SIGNATURES) {
      const m = sig.re.exec(res.body);
      if (!m) continue;
      return [
        {
          checkId: 'SEC-07',
          title: 'Error pages reveal how your server is built',
          severity: 'medium',
          confidence: sig.confidence,
          url: probe,
          why: 'Error pages that print stack traces or debug screens show file paths, library versions and sometimes secrets. That gives attackers a map of your app.',
          evidence: { request: `GET ${probe}`, status: res.status, excerpt: m[0].replace(/\s+/g, ' ').slice(0, 160) },
          reproduce: curlFor(probe) + ' | head -20',
          fixPrompt:
            `This app shows detailed error output (stack traces or a debug page) for a request to a path that does not exist. Please:\n` +
            `1. Run the production build with NODE_ENV=production (or DEBUG=False) so detailed errors are off.\n` +
            `2. Add a generic error handler that returns a short message like "Something went wrong" and logs the details on the server only.\n` +
            `3. Return a plain 404 page for unknown routes.\n` +
            `Then run: npx vibeprobe ${surface.origin} --recheck SEC-07`,
        },
      ];
    }
    return [];
  },
};
