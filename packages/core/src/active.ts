import { ActiveModeError } from './errors';
import { isLocalHost } from './scope';

const brand = Symbol('vibeprobe.active-consent');

/**
 * Proof that the user knowingly turned on active mode for one local target.
 * It cannot be built with `new`: the only way is grantActiveConsent(), which refuses
 * anything that is not localhost. GuardedHttpClient will not send a write method without one.
 */
export class ActiveConsent {
  readonly [brand] = true;
  readonly host: string;
  /** @internal use grantActiveConsent() */
  constructor(host: string, key: typeof brand) {
    if (key !== brand) throw new ActiveModeError('Use grantActiveConsent() to enable active mode.');
    this.host = host;
  }
}

export interface ConsentRequest {
  target: URL;
  /** True only after the user said yes (an interactive prompt or --yes). */
  acknowledged: boolean;
}

/**
 * Active mode sends attack-like requests (POST, PUT, PATCH with test payloads). It is local-only:
 * even a verified public domain is refused, because the user's own dev database is the only
 * place where junk test data is acceptable.
 */
export function grantActiveConsent({ target, acknowledged }: ConsentRequest): ActiveConsent {
  if (!acknowledged) {
    throw new ActiveModeError('Active mode needs your confirmation: it sends test payloads that can leave junk data in your database.');
  }
  if (!isLocalHost(target.hostname)) {
    throw new ActiveModeError(`Active mode only runs against localhost, not ${target.hostname}.`);
  }
  return new ActiveConsent(target.hostname, brand);
}

export function isActiveConsent(value: unknown): value is ActiveConsent {
  return value instanceof ActiveConsent && (value as { [brand]?: boolean })[brand] === true;
}
