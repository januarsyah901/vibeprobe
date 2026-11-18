import type { Finding, Severity } from '@vibeprobe/core';
import { fingerprint } from './baseline';

/** GitHub code scanning: error/warning/note, plus a 0-10 "security-severity" that sorts the Security tab. */
const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = { critical: 'error', high: 'error', medium: 'warning', low: 'note' };
const SECURITY_SEVERITY: Record<Severity, string> = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0' };

interface SarifOptions {
  version: string;
  target: string;
}

/**
 * Builds a SARIF 2.1.0 log. Findings are web endpoints, not source files, so the "file" is the
 * endpoint path under the host name (for example "localhost/api/users"). The same finding keeps the
 * same fingerprint across runs, so GitHub tracks it as one alert instead of opening a new one each time.
 */
export function toSarif(findings: Finding[], { version, target }: SarifOptions) {
  const rules = new Map<string, Finding>();
  for (const f of findings) if (!rules.has(f.checkId)) rules.set(f.checkId, f);
  const host = new URL(target).hostname;

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'vibeprobe',
            version,
            informationUri: 'https://github.com/januarsyah901/vibeprobe',
            rules: [...rules.values()].map((f) => ({
              id: f.checkId,
              name: f.checkId.replace('-', ''),
              shortDescription: { text: f.title },
              fullDescription: { text: f.why },
              help: { text: f.fixPrompt, markdown: `${f.why}\n\n**Fix prompt (paste into your AI coding tool):**\n\n\`\`\`text\n${f.fixPrompt}\n\`\`\`` },
              defaultConfiguration: { level: LEVEL[f.severity] },
              properties: { 'security-severity': SECURITY_SEVERITY[f.severity], tags: ['security', f.checkId.startsWith('ACT') ? 'active' : 'passive'] },
            })),
          },
        },
        results: findings.map((f) => ({
          ruleId: f.checkId,
          level: LEVEL[f.severity],
          message: { text: `${f.title}. ${f.why}` },
          locations: [{ physicalLocation: { artifactLocation: { uri: `${host}${new URL(f.url).pathname}` } } }],
          partialFingerprints: { 'vibeprobe/v1': fingerprint(f) },
          properties: { confidence: f.confidence, severity: f.severity, url: f.url, reproduce: f.reproduce },
        })),
      },
    ],
  };
}
