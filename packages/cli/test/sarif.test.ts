import { describe, expect, it } from 'vitest';
import type { Finding } from '@vibeprobe/core';
import { toSarif } from '../src/sarif';

const f = (over: Partial<Finding> = {}): Finding => ({
  checkId: 'SEC-03',
  title: '/api/users returns data to anyone, no login needed',
  severity: 'high',
  confidence: 'high',
  url: 'http://localhost:3000/api/users',
  why: 'Anyone can read it.',
  evidence: { request: 'GET /api/users', status: 200, excerpt: 'fields: email' },
  reproduce: "curl -sS -i 'http://localhost:3000/api/users'",
  fixPrompt: 'x'.repeat(50),
  ...over,
});

describe('toSarif', () => {
  const sarif = toSarif(
    [f(), f({ checkId: 'ACT-01', severity: 'medium', title: 'XSS', url: 'http://localhost:3000/search' }), f({ severity: 'critical', url: 'http://localhost:3000/api/other' })],
    { version: '9.9.9', target: 'http://localhost:3000/' },
  );
  const run = sarif.runs[0]!;

  it('is SARIF 2.1.0 with the tool name and version', () => {
    expect(sarif.version).toBe('2.1.0');
    expect(run.tool.driver).toMatchObject({ name: 'vibeprobe', version: '9.9.9' });
  });

  it('has one rule per check id, with a fix prompt in the help', () => {
    expect(run.tool.driver.rules.map((r) => r.id).sort()).toEqual(['ACT-01', 'SEC-03']);
    expect(run.tool.driver.rules[0]!.help.markdown).toContain('Fix prompt');
  });

  it('maps severity to level and security-severity', () => {
    const levels = Object.fromEntries(run.results.map((r) => [`${r.ruleId}:${r.properties.severity}`, r.level]));
    expect(levels).toEqual({ 'SEC-03:high': 'error', 'ACT-01:medium': 'warning', 'SEC-03:critical': 'error' });
    const act = run.tool.driver.rules.find((r) => r.id === 'ACT-01')!;
    expect(act.properties['security-severity']).toBe('5.5');
    expect(act.properties.tags).toContain('active');
  });

  it('uses host + path as the location, since findings are endpoints, not files', () => {
    expect(run.results[0]!.locations[0]!.physicalLocation.artifactLocation.uri).toBe('localhost/api/users');
  });

  it('gives each finding a stable fingerprint that ignores the port', () => {
    const a = toSarif([f()], { version: '1', target: 'http://localhost:3000/' }).runs[0]!.results[0]!.partialFingerprints['vibeprobe/v1'];
    const b = toSarif([f({ url: 'http://localhost:5173/api/users' })], { version: '1', target: 'http://localhost:5173/' }).runs[0]!.results[0]!.partialFingerprints['vibeprobe/v1'];
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{16}$/);
  });

  it('is valid for no findings', () => {
    expect(toSarif([], { version: '1', target: 'http://localhost:3000/' }).runs[0]!.results).toEqual([]);
  });
});
