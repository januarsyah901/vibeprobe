import { describe, expect, it } from 'vitest';
import type { Finding } from '@vibeprobe/core';
import { escapeHtml, toHtml } from '../src/report-html';

const base: Finding = {
  checkId: 'SEC-06',
  title: 'Environment file (.env) can be downloaded by anyone',
  severity: 'critical',
  confidence: 'high',
  url: 'http://localhost:4010/.env',
  why: 'The file holds your passwords and API keys.',
  evidence: { request: 'GET http://localhost:4010/.env', status: 200, excerpt: 'DATABASE_URL=po************' },
  reproduce: "curl -sS -i 'http://localhost:4010/.env'",
  fixPrompt: 'The file /.env is publicly downloadable.\n1. Serve only a public folder.',
};
const low: Finding = {
  ...base,
  checkId: 'SEC-03',
  title: '/api/orders returns data to anyone, no login needed',
  severity: 'high',
  confidence: 'low',
  url: 'http://localhost:4010/api/orders',
};
const meta = { target: 'http://localhost:4010/', version: '0.1.0', generatedAt: new Date('2026-11-09T09:30:00Z') };

describe('toHtml', () => {
  it('matches the snapshot', () => {
    expect(toHtml([base, low], meta)).toMatchSnapshot();
  });

  it('shows "Fix these first" only for high-confidence findings, and a separate low-confidence section', () => {
    const html = toHtml([base, low], meta);
    expect(html).toContain('Fix these first');
    expect(html).toContain('Needs a human look');
    const first = html.slice(html.indexOf('Fix these first'), html.indexOf('All findings'));
    expect(first).toContain('Environment file');
    expect(first).not.toContain('/api/orders');
  });

  it('says so when there is nothing to report', () => {
    const html = toHtml([], meta);
    expect(html).toContain('No findings.');
    expect(html).not.toContain('Fix these first');
  });

  it('escapes everything that comes from the target, so a hostile app cannot inject script', () => {
    const evil: Finding = {
      ...base,
      title: '<script>alert(1)</script>',
      url: 'http://x/"><img src=x onerror=alert(1)>',
      evidence: { request: '<b>GET</b>', excerpt: '</pre><script>alert(2)</script>' },
      fixPrompt: '<iframe src=//evil></iframe>',
    };
    const html = toHtml([evil], { ...meta, target: '<script>alert(3)</script>' });
    // Only our own inline script (the copy button) may exist.
    expect(html.match(/<script/g)).toHaveLength(1);
    expect(html).not.toContain('<img src=x');
    expect(html).not.toContain('<iframe');
    expect(html).not.toContain('<b>GET</b>');
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
  });

  it('is self-contained: no external requests of any kind', () => {
    const html = toHtml([base, low], meta);
    expect(html).not.toMatch(/<link\b/i);
    expect(html).not.toMatch(/<script[^>]*\bsrc=/i);
    expect(html).not.toMatch(/<img\b/i);
    expect(html).not.toMatch(/@import|url\(/i);
    expect(html).not.toMatch(/\b(?:href|src)=["']https?:/i);
    expect(html).not.toMatch(/\b(?:fetch|XMLHttpRequest|sendBeacon|WebSocket)\b/);
  });

  it('supports light and dark and has accessible basics', () => {
    const html = toHtml([base], meta);
    expect(html).toContain('prefers-color-scheme:dark');
    expect(html).toContain('<html lang="en">');
    expect(html).toContain('name="viewport"');
    expect(html).toContain('<title>vibeprobe report: http://localhost:4010/</title>');
  });
});

describe('escapeHtml', () => {
  it('escapes the five dangerous characters', () => {
    expect(escapeHtml(`<a href="x" onclick='y'>&`)).toBe('&lt;a href=&quot;x&quot; onclick=&#39;y&#39;&gt;&amp;');
  });
});
