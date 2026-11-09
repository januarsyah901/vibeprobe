import type { Check } from '@vibeprobe/core';
import { sec01 } from './sec01-secrets-in-bundle';
import { sec06 } from './sec06-sensitive-files';
import { sec08 } from './sec08-cors';
import { sec09 } from './sec09-security-headers';
import { sec11 } from './sec11-source-maps';

export { sec01, sec06, sec08, sec09, sec11 };

/** Checks that run by default. More arrive as they get their vulnerable + safe fixtures. */
export const allChecks: Check[] = [sec01, sec06, sec08, sec09, sec11];
