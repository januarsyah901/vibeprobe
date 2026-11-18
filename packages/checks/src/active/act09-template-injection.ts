import { type Check, type Finding } from '@vibeprobe/core';
import { injectionPoints, sendInput } from './util';

// 1337 * 7331 = 9801547: a number that never appears by accident.
const PRODUCT = '9801547';
const PAYLOAD = '{{1337*7331}} ${1337*7331} <%= 1337*7331 %> #{1337*7331}';

export const act09: Check = {
  id: 'ACT-09',
  title: 'Server-side template injection',
  severity: 'critical',
  mode: 'active',
  intensity: 'full',
  async run({ client, surface }) {
    const findings: Finding[] = [];
    for (const point of injectionPoints(surface, 8)) {
      const { res, request, curl } = await sendInput(client, point, PAYLOAD);
      if (res.status < 200 || res.status >= 400 || !res.body.includes(PRODUCT)) continue;
      const path = new URL(point.url).pathname;
      findings.push({
        checkId: 'ACT-09',
        title: `The "${point.param}" input on ${path} is run as template code`,
        severity: 'critical',
        confidence: 'high',
        url: point.url,
        why: 'We sent a sum and the page showed its answer, so the input is executed by the template engine. On most engines this lets an attacker run commands on your server.',
        evidence: { request, status: res.status, excerpt: `1337*7331 came back as ${PRODUCT}` },
        reproduce: curl,
        fixPrompt:
          `The "${point.param}" input on ${path} is evaluated by the template engine (1337*7331 came back as ${PRODUCT}). Please:\n` +
          `1. Never build a template string from user input. Pass user data as a variable to a fixed template instead.\n` +
          `2. Make sure the value is escaped when printed.\n` +
          `Then run: npx vibeprobe ${surface.origin} --active=full --recheck ACT-09`,
      });
    }
    return findings;
  },
};
