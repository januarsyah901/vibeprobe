/** Keeps the first few characters of a secret and stars out the rest (PRD: secrets are always masked). */
export function maskSecret(secret: string, visible = 4): string {
  if (secret.length <= visible) return '*'.repeat(secret.length);
  return secret.slice(0, visible) + '*'.repeat(Math.min(secret.length - visible, 12));
}

/** Masks the values in KEY=value lines, keeping the names. Used for exposed .env files. */
export function maskEnvLines(text: string, maxLines = 10): string {
  return text
    .split(/\r?\n/)
    .filter((l) => /^[A-Za-z_][A-Za-z0-9_]*\s*=/.test(l))
    .slice(0, maxLines)
    .map((l) => {
      const i = l.indexOf('=');
      return `${l.slice(0, i)}=${maskSecret(l.slice(i + 1).trim().replace(/^['"]|['"]$/g, ''), 2)}`;
    })
    .join('\n');
}
