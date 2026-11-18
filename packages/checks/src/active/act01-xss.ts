import { type Check, type Finding } from '@vibeprobe/core';
import { injectionPoints, isHtml, marker, sendInput } from './util';

export const act01: Check = {
  id: 'ACT-01',
  title: 'Reflected cross-site scripting (XSS)',
  severity: 'high',
  mode: 'active',
  intensity: 'light',
  async run({ client, surface }) {
    const findings: Finding[] = [];
    for (const point of injectionPoints(surface, 10)) {
      const m = marker();
      const tag = `<${m}>`;
      const { res, request, curl } = await sendInput(client, point, `"'${tag}`);
      if (res.status < 200 || res.status >= 400 || !isHtml(res) || !res.body.includes(tag)) continue;
      const path = new URL(point.url).pathname;
      findings.push({
        checkId: 'ACT-01',
        title: `The "${point.param}" input on ${path} is shown back without escaping`,
        severity: 'high',
        confidence: 'high',
        url: point.url,
        why: 'Text a visitor sends comes back in the page as real HTML. An attacker can craft a link that runs their script in your users\' browsers and steals their session.',
        evidence: { request, status: res.status, excerpt: `the harmless test tag ${tag} came back unescaped in the HTML` },
        reproduce: curl,
        fixPrompt:
          `The "${point.param}" input on ${path} is written into the HTML response without escaping (a test tag came back as real markup). Please:\n` +
          `1. Escape the value for HTML wherever it is printed. Use the framework's normal templating, and never build HTML by joining strings or use innerHTML / dangerouslySetInnerHTML with user input.\n` +
          `2. Add a Content-Security-Policy header that blocks inline scripts.\n` +
          `Then run: npx vibeprobe ${surface.origin} --active --recheck ACT-01`,
      });
    }
    return findings;
  },
};
