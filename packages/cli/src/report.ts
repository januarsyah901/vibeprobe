import type { Finding, Severity } from '@vibeprobe/core';

const LABEL: Record<Severity, string> = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW' };

export function toMarkdown(target: string, findings: Finding[]): string {
  const lines = [`# vibeprobe report`, '', `Target: ${target}`, `Findings: ${findings.length}`, ''];
  if (findings.length === 0) lines.push('No findings.');
  for (const f of findings) {
    lines.push(
      `## [${LABEL[f.severity]}] ${f.title} (${f.checkId})`,
      '',
      `Confidence: ${f.confidence} · ${f.url}`,
      '',
      f.why,
      '',
      'Evidence:',
      '```',
      f.evidence.request,
      f.evidence.excerpt,
      '```',
      '',
      'Reproduce (read-only):',
      '```bash',
      f.reproduce,
      '```',
      '',
      'Fix prompt (paste into your AI coding tool):',
      '```text',
      f.fixPrompt,
      '```',
      '',
    );
  }
  return lines.join('\n');
}

export function summary(findings: Finding[]): string {
  if (findings.length === 0) return 'No findings. Nice';
  const counts = findings.reduce<Record<string, number>>((m, f) => ((m[f.severity] = (m[f.severity] ?? 0) + 1), m), {});
  const parts = (['critical', 'high', 'medium', 'low'] as const).filter((s) => counts[s]).map((s) => `${counts[s]} ${s}`);
  return `${findings.length} finding${findings.length > 1 ? 's' : ''}: ${parts.join(', ')}`;
}
