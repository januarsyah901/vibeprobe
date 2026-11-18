import { curlFor, maskEnvLines, type Check, type Finding, type Severity } from '@vibeprobe/core';

interface Probe {
  path: string;
  label: string;
  severity: Severity;
  /** Must match for the response to count: a 200 alone proves nothing (SPAs answer 200 to everything). */
  signature: RegExp;
  excerpt: (body: string) => string;
  why: string;
  /** What to do besides "stop serving it". */
  extraFix: string;
  /** Directory listings are HTML pages on purpose. */
  allowHtml?: boolean;
}

const first = (n: number) => (b: string) => b.split(/\r?\n/).slice(0, n).join('\n').slice(0, 300);

const PROBES: Probe[] = [
  {
    path: '/.env',
    label: 'Environment file (.env)',
    severity: 'critical',
    signature: /^[A-Z][A-Z0-9_]{2,}\s*=\s*\S+/m,
    excerpt: (b) => maskEnvLines(b),
    why: 'The file holds your passwords and API keys, and the web server hands it to anyone who asks.',
    extraFix: 'Treat every value in that file as leaked: rotate all keys and passwords.',
  },
  {
    path: '/.git/HEAD',
    label: 'Git repository (.git/HEAD)',
    severity: 'critical',
    signature: /^ref:\s+refs\/heads\//,
    excerpt: (b) => b.trim().slice(0, 80),
    why: 'Anyone can download your project history from the web server, including code and sometimes secrets that were deleted later.',
    extraFix: 'Remove the .git folder from the deployed files.',
  },
  {
    path: '/.git/config',
    label: 'Git config (.git/config)',
    severity: 'critical',
    signature: /^\[core\]/m,
    excerpt: (b) => b.split(/\r?\n/).slice(0, 4).join('\n').replace(/(url\s*=\s*https?:\/\/)[^@\s]+@/, '$1****@'),
    why: 'Anyone can download your project history from the web server, including code and sometimes secrets that were deleted later.',
    extraFix: 'Remove the .git folder from the deployed files.',
  },
  {
    path: '/backup.sql',
    label: 'Database dump (backup.sql)',
    severity: 'critical',
    signature: /(CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump)/i,
    excerpt: (b) => first(2)(b).replace(/VALUES\s*\(.*/i, 'VALUES (****)'),
    why: 'A database dump is your whole database in one file: users, emails, password hashes, everything. Anyone can download it.',
    extraFix: 'Delete the dump from the web folder, store backups outside it, and assume the data inside has leaked.',
  },
  {
    path: '/.npmrc',
    label: 'npm config (.npmrc)',
    severity: 'critical',
    signature: /_authToken\s*=|:_password\s*=/,
    excerpt: (b) => b.replace(/(=\s*)\S+/g, '$1****').slice(0, 200),
    why: 'This file can contain an npm publish token. Whoever holds it can publish packages as you.',
    extraFix: 'Revoke the npm token in your npm account and create a new one.',
  },
  {
    path: '/.aws/credentials',
    label: 'AWS credentials file',
    severity: 'critical',
    signature: /aws_access_key_id\s*=/i,
    excerpt: (b) => b.replace(/(=\s*)\S+/g, '$1****').slice(0, 200),
    why: 'This file holds AWS keys. Anyone who downloads it can act as your AWS account.',
    extraFix: 'Deactivate those AWS keys now and create new ones.',
  },
  {
    path: '/actuator/env',
    label: 'Spring Boot environment endpoint (/actuator/env)',
    severity: 'high',
    signature: /"propertySources"\s*:/,
    excerpt: () => 'response lists the app environment (values not shown)',
    why: 'This management endpoint lists the app\'s configuration, which often includes database URLs and keys.',
    extraFix: 'Disable the actuator endpoints you do not need, or put them behind authentication on a private port.',
  },
  {
    path: '/metrics',
    label: 'Prometheus metrics (/metrics)',
    severity: 'medium',
    signature: /^# (HELP|TYPE) \w+/m,
    excerpt: first(3),
    why: 'Metrics reveal routes, traffic volume, versions and internal names. They help an attacker plan.',
    extraFix: 'Serve /metrics only on an internal network or behind authentication.',
  },
  {
    path: '/phpinfo.php',
    label: 'PHP info page (phpinfo.php)',
    severity: 'medium',
    signature: /<title>phpinfo\(\)|PHP Version \d/i,
    excerpt: () => 'phpinfo() page is public',
    why: 'phpinfo() prints server paths, modules and environment values to anyone who asks.',
    extraFix: 'Delete phpinfo.php from the server.',
    allowHtml: true,
  },
  {
    path: '/server-status',
    label: 'Apache server status (/server-status)',
    severity: 'medium',
    signature: /Apache Server Status/i,
    excerpt: () => 'Apache server status page is public',
    why: 'The page shows live requests, client addresses and internal URLs.',
    extraFix: 'Restrict /server-status to localhost in the Apache config.',
    allowHtml: true,
  },
  {
    path: '/.DS_Store',
    label: 'macOS folder index (.DS_Store)',
    severity: 'low',
    signature: /^\u0000\u0000\u0000\u0001Bud1/,
    excerpt: () => 'a .DS_Store file lists file names from your project folder',
    why: 'This file lists the names of files in the folder it came from, including ones that were never meant to be public.',
    extraFix: 'Delete .DS_Store files from the deployed folder and add .DS_Store to .gitignore.',
  },
  ...['/uploads/', '/backup/', '/files/'].map(
    (path): Probe => ({
      path,
      label: `Directory listing (${path})`,
      severity: 'medium',
      signature: /<title>Index of \/|<h1>Index of \//i,
      excerpt: () => 'the server lists every file in this folder',
      why: 'The server shows the full list of files in this folder, so anyone can browse and download them.',
      extraFix: 'Turn off directory listing in the web server config (for nginx: "autoindex off;").',
      allowHtml: true,
    }),
  ),
];

export const sec06: Check = {
  id: 'SEC-06',
  title: 'Sensitive file exposed',
  severity: 'critical',
  async run({ client, surface }) {
    const findings: Finding[] = [];
    for (const probe of PROBES) {
      const url = new URL(probe.path, surface.origin).href;
      const res = await client.request(url);
      const html = (res.headers.get('content-type') ?? '').includes('text/html');
      if (res.status !== 200 || (html && !probe.allowHtml) || !probe.signature.test(res.body)) continue;
      findings.push({
        checkId: 'SEC-06',
        title: `${probe.label} can be downloaded by anyone`,
        severity: probe.severity,
        confidence: 'high',
        url,
        why: probe.why,
        evidence: { request: `GET ${url}`, status: 200, excerpt: probe.excerpt(res.body) },
        reproduce: curlFor(url),
        fixPrompt:
          `The file ${probe.path} is publicly reachable on this app. Please:\n` +
          `1. Make sure the web server only serves a dedicated public folder (for Next.js "public/", for Vite the "dist/" build output) and never the project root.\n` +
          `2. Add a rule that blocks requests for dotfiles (any path starting with ".") and for backup or dump files in the server or hosting config.\n` +
          `3. ${probe.extraFix}\n` +
          `Then run: npx vibeprobe ${surface.origin} --recheck SEC-06`,
      });
    }
    return findings;
  },
};
