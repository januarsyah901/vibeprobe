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

export { sec01, sec03, sec04, sec06, sec07, sec08, sec09, sec10, sec11 };
export { parseSetCookie } from './sec10-cookie-flags';
export { findPiiKeys } from './sec03-unauthenticated-api';

/** Checks that run by default. A check joins this list only with a vulnerable and a safe fixture. */
export const allChecks: Check[] = [sec01, sec03, sec04, sec06, sec07, sec08, sec09, sec10, sec11];
