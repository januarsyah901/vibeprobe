import type { Check } from '@vibeprobe/core';
import { sec01 } from './sec01-secrets-in-bundle';
import { sec03 } from './sec03-unauthenticated-api';
import { sec04 } from './sec04-admin-pages';
import { sec06 } from './sec06-sensitive-files';
import { sec07 } from './sec07-debug-mode';
import { sec08 } from './sec08-cors';
import { sec09 } from './sec09-security-headers';
import { sec10 } from './sec10-cookie-flags';
import { sec11 } from './sec11-source-maps';
import { sec12 } from './sec12-api-docs';
import { sec13 } from './sec13-secrets-in-responses';
import { sec14 } from './sec14-jwt-analysis';
import { sec15 } from './sec15-open-redirect';
import { act01 } from './active/act01-xss';
import { act02 } from './active/act02-sql-injection';
import { act03 } from './active/act03-csrf';
import { act04 } from './active/act04-path-traversal';
import { act05 } from './active/act05-attempt-limit';
import { act06 } from './active/act06-write-without-login';
import { act07 } from './active/act07-mass-assignment';
import { act08 } from './active/act08-nosql-injection';
import { act09 } from './active/act09-template-injection';
import { act10 } from './active/act10-ssrf';
import { act11 } from './active/act11-host-header';
import { act12 } from './active/act12-forced-browsing';
import { act13 } from './active/act13-prototype-pollution';

export { sec01, sec03, sec04, sec06, sec07, sec08, sec09, sec10, sec11, sec12, sec13, sec14, sec15 };
export { act01, act02, act03, act04, act05, act06, act07, act08, act09, act10, act11, act12, act13 };
export { parseSetCookie } from './sec10-cookie-flags';
export { findPiiKeys } from './sec03-unauthenticated-api';

/** Checks that run by default. A check joins this list only with a vulnerable and a safe fixture. */
export const allChecks: Check[] = [sec01, sec03, sec04, sec06, sec07, sec08, sec09, sec10, sec11, sec12, sec13, sec14, sec15];

/** Checks that run only with --active (localhost only). Same fixture rule as the passive ones. */
export const activeChecks: Check[] = [act01, act02, act03, act04, act05, act06, act07, act08, act09, act10, act11, act12, act13];

export type ActiveIntensity = 'light' | 'full';

/** light: the cheap, low-noise checks. full: everything. */
export function activeChecksFor(intensity: ActiveIntensity): Check[] {
  return intensity === 'full' ? activeChecks : activeChecks.filter((c) => (c.intensity ?? 'light') === 'light');
}
