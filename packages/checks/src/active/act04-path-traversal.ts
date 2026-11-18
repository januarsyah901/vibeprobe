import { type Check, type Finding } from '@vibeprobe/core';
import { injectionPoints, sendInput } from './util';

const FILE_PARAM = /^(file|filename|path|page|name|doc|document|template|f|dir|folder|include|view|lang|img|image|download|attachment)$/i;
const PAYLOADS = ['../../../../../../etc/passwd', '....//....//....//....//etc/passwd', '..\\..\\..\\..\\windows\\win.ini'];
const SIGNATURE = /root:[^:\n]*:0:0:|\[(fonts|extensions)\]/i;

export const act04: Check = {
  id: 'ACT-04',
  title: 'Path traversal',
  severity: 'critical',
  mode: 'active',
  intensity: 'light',
  async run({ client, surface }) {
    const findings: Finding[] = [];
    for (const point of injectionPoints(surface, 30).filter((p) => FILE_PARAM.test(p.param)).slice(0, 6)) {
      for (const payload of PAYLOADS) {
        const { res, request, curl } = await sendInput(client, point, payload);
        if (res.status !== 200 || !SIGNATURE.test(res.body)) continue;
        const path = new URL(point.url).pathname;
        findings.push({
          checkId: 'ACT-04',
          title: `The "${point.param}" input on ${path} can read files outside its folder`,
          severity: 'critical',
          confidence: 'high',
          url: point.url,
          why: 'Adding "../" to the file name made the server return a system file. An attacker can read any file the app can read: source code, .env files, keys.',
          evidence: { request, status: 200, excerpt: 'the response contains the contents of a system file (not shown)' },
          reproduce: curl,
          fixPrompt:
            `The "${point.param}" input on ${path} is used as a file path and "../" escapes the intended folder. Please:\n` +
            `1. Do not build file paths from user input. Map an id or a fixed allowlist of names to files instead.\n` +
            `2. If a name must be accepted, resolve the full path and reject it unless it is still inside the allowed folder (path.resolve + startsWith).\n` +
            `3. Reject any value containing "..", "/" or "\\".\n` +
            `Then run: npx vibeprobe ${surface.origin} --active --recheck ACT-04`,
        });
        break;
      }
    }
    return findings;
  },
};
