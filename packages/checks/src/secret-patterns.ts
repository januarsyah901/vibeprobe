export interface SecretPattern {
  name: string;
  re: RegExp;
  /** Return false to ignore a match (e.g. a public key). */
  accept?: (match: string) => boolean;
}

export interface Jwt {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
}

export const JWT_RE = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*(?![A-Za-z0-9_-])/g;

export function parseJwt(token: string): Jwt | undefined {
  try {
    const [h, p] = token.split('.');
    const header = JSON.parse(Buffer.from(h!, 'base64url').toString('utf8')) as unknown;
    const payload = JSON.parse(Buffer.from(p!, 'base64url').toString('utf8')) as unknown;
    if (typeof header !== 'object' || header === null || typeof payload !== 'object' || payload === null) return undefined;
    return { header: header as Record<string, unknown>, payload: payload as Record<string, unknown> };
  } catch {
    return undefined;
  }
}

export function jwtRole(token: string): string | undefined {
  const role = parseJwt(token)?.payload.role;
  return typeof role === 'string' ? role : undefined;
}

export const SECRET_PATTERNS: SecretPattern[] = [
  { name: 'Stripe secret key', re: /\bsk_live_[0-9A-Za-z]{16,}\b/g },
  { name: 'AWS access key ID', re: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: 'GitHub token', re: /\bgh[pousr]_[0-9A-Za-z]{30,}\b/g },
  { name: 'Private key', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g },
  { name: 'Slack token', re: /\bxox[abprs]-[0-9A-Za-z-]{20,}\b/g },
  {
    // Supabase anon keys are public by design: only the service_role key is a leak.
    name: 'Supabase service_role key',
    re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    accept: (m) => jwtRole(m) === 'service_role',
  },
];
