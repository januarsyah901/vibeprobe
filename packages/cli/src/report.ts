import type { Finding, Severity } from '@vibeprobe/core';

const LABEL: Record<Severity, string> = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW' };

export function toMarkdown(target: string, all: Finding[]): string {
  const findings = all.filter((f) => f.confidence !== 'low');
  const lowConfidence = all.filter((f) => f.confidence === 'low');
  const lines = [`# vibeprobe report`, '', `Target: ${target}`, `Findings: ${findings.length}`, ''];
  if (findings.length === 0) lines.push('No findings.', '');
  if (findings.length > 0) {
    const top = findings.filter((f) => f.confidence === 'high').slice(0, 3);
    if (top.length > 0) {
      lines.push('## Fix these first', '', ...top.map((f, i) => `${i + 1}. **${f.title}** (${f.checkId}, ${f.severity})`), '');
    }
  }
  const render = (f: Finding) => {
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
  };
  findings.forEach(render);
  if (lowConfidence.length > 0) {
    lines.push(
      '# Needs a human look',
      '',
      'Low confidence: vibeprobe could not prove these. They do not fail CI. Check whether they are intended.',
      '',
    );
    lowConfidence.forEach(render);
  }
  return lines.join('\n');
}

export function summary(all: Finding[]): string {
  const findings = all.filter((f) => f.confidence !== 'low');
  const low = all.length - findings.length;
  const note = low > 0 ? ` (+${low} low-confidence to review)` : '';
  if (findings.length === 0) return `No findings. Nice${note}`;
  const counts = findings.reduce<Record<string, number>>((m, f) => ((m[f.severity] = (m[f.severity] ?? 0) + 1), m), {});
  const parts = (['critical', 'high', 'medium', 'low'] as const).filter((s) => counts[s]).map((s) => `${counts[s]} ${s}`);
  return `${findings.length} finding${findings.length > 1 ? 's' : ''}: ${parts.join(', ')}${note}`;
}
