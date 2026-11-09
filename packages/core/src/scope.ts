import { BlockList, isIP } from 'node:net';
import { ScopeError } from './errors';

const ALLOWED_PROTOCOLS = new Set(['http:', 'https:']);

const loopback = new BlockList();
loopback.addSubnet('127.0.0.0', 8, 'ipv4');
loopback.addAddress('::1', 'ipv6');

/**
 * Addresses a verified public host must never resolve to. If a public domain suddenly
 * points here, someone is trying to aim the scanner at an internal network (DNS rebinding).
 */
const internal = new BlockList();
for (const [net, prefix] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.168.0.0', 16],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
] as const) {
  internal.addSubnet(net, prefix, 'ipv4');
}
for (const [net, prefix] of [
  ['::', 128],
  ['::1', 128],
  ['fc00::', 7],
  ['fe80::', 10],
  ['ff00::', 8],
] as const) {
  internal.addSubnet(net, prefix, 'ipv6');
}

/** Lowercases a hostname and strips IPv6 brackets and a trailing dot. */
export function normalizeHost(host: string): string {
  let h = host.trim().toLowerCase();
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);
  if (h.endsWith('.')) h = h.slice(0, -1);
  return h;
}

/** Unwraps IPv4-mapped IPv6 addresses (::ffff:127.0.0.1 → 127.0.0.1). */
function unmapIPv4(ip: string): string {
  const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  return m ? m[1]! : ip;
}

function check(list: BlockList, ip: string): boolean {
  const addr = unmapIPv4(normalizeHost(ip));
  const family = isIP(addr);
  if (family === 0) return false;
  return list.check(addr, family === 4 ? 'ipv4' : 'ipv6');
}

export function isLoopbackAddress(ip: string): boolean {
  return check(loopback, ip);
}

export function isInternalAddress(ip: string): boolean {
  return check(internal, ip);
}

/** localhost, *.localhost, and loopback IP literals. */
export function isLocalHost(host: string): boolean {
  const h = normalizeHost(host);
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  return isIP(unmapIPv4(h)) !== 0 && isLoopbackAddress(h);
}

export interface ScopeOptions {
  /**
   * Public hostnames whose ownership the user has proven (see PRD F2).
   * Empty by default: only local targets are allowed.
   */
  verifiedHosts?: Iterable<string>;
}

/**
 * Decides where vibeprobe may send requests. Every outgoing request is checked twice:
 * once on the URL before anything happens, and once on the resolved IP right before connecting.
 */
export class Scope {
  readonly #verified: Set<string>;

  constructor(options: ScopeOptions = {}) {
    this.#verified = new Set([...(options.verifiedHosts ?? [])].map(normalizeHost));
  }

  isVerifiedHost(host: string): boolean {
    return this.#verified.has(normalizeHost(host));
  }

  /** Throws ScopeError unless the URL is http(s) and its host is local or verified. */
  assertUrl(url: URL): void {
    if (!ALLOWED_PROTOCOLS.has(url.protocol)) {
      throw new ScopeError(`Protocol ${url.protocol} is not allowed; use http or https.`);
    }
    if (url.username || url.password) {
      throw new ScopeError('URLs with embedded credentials are not allowed.');
    }
    const host = normalizeHost(url.hostname);
    if (isLocalHost(host)) return;
    if (isIP(unmapIPv4(host)) !== 0) {
      throw new ScopeError(
        `${host} is not a loopback address. Only local targets can be scanned by IP.`,
      );
    }
    if (this.isVerifiedHost(host)) return;
    throw new ScopeError(
      `${host} is outside the scan scope. vibeprobe only scans localhost by default; ` +
        'a public domain must be verified as yours first.',
    );
  }

  /**
   * Throws ScopeError if a hostname resolved to an address it must not reach:
   * local names must stay on loopback, verified public names must stay off internal ranges.
   */
  assertResolvedAddress(hostname: string, address: string): void {
    const host = normalizeHost(hostname);
    if (isLocalHost(host)) {
      if (!isLoopbackAddress(address)) {
        throw new ScopeError(
          `${host} resolved to ${address}, which is not a loopback address (possible DNS rebinding).`,
        );
      }
      return;
    }
    if (!this.isVerifiedHost(host)) {
      throw new ScopeError(`${host} is outside the scan scope.`);
    }
    if (isInternalAddress(address)) {
      throw new ScopeError(
        `${host} resolved to internal address ${address} (possible DNS rebinding).`,
      );
    }
  }
}
