import { type Check, type Finding } from '@vibeprobe/core';
import { injectionPoints, sendInput } from './util';

const DB_ERROR =
  /(SQL syntax|SQLITE_ERROR|SQLite3::|unrecognized token|PG::\w+|psql:|syntax error at or near|unterminated quoted string|ORA-\d{5}|ODBC|mysqli?_|SequelizeDatabaseError|PrismaClientKnownRequestError|SQLSTATE\[|Unclosed quotation mark|near ".*": syntax error)/i;

/** Error-based only: one single quote, then look for a database error. Nothing is read, changed or guessed. */
export const act02: Check = {
  id: 'ACT-02',
  title: 'SQL injection (error-based)',
  severity: 'critical',
  mode: 'active',
  intensity: 'light',
  async run({ client, surface }) {
    const findings: Finding[] = [];
    for (const point of injectionPoints(surface, 10)) {
      const { res, request, curl } = await sendInput(client, point, `test'`);
      const m = DB_ERROR.exec(res.body);
      if (!m) continue;
      // The same input without the quote must not already show that text.
      const base = await sendInput(client, point, 'test');
      if (DB_ERROR.test(base.res.body)) continue;
      const path = new URL(point.url).pathname;
      findings.push({
        checkId: 'ACT-02',
        title: `The "${point.param}" input on ${path} breaks the database query`,
        severity: 'critical',
        confidence: 'high',
        url: point.url,
        why: 'A single quote in the input produced a database error, so the input is pasted straight into a SQL query. An attacker can read or change your whole database through it.',
        evidence: { request, status: res.status, excerpt: `database error text in the response: "${m[0].slice(0, 80)}"` },
        reproduce: curl,
        fixPrompt:
          `The "${point.param}" input on ${path} is put into a SQL query by string concatenation (a single quote caused a database error). Please:\n` +
          `1. Rewrite the query to use parameters or the ORM's safe query builder (placeholders like $1 or ?), never string concatenation or template literals.\n` +
          `2. Validate the type of the input (for an id, require a number).\n` +
          `3. Stop returning raw database errors to the browser.\n` +
          `Then run: npx vibeprobe ${surface.origin} --active --recheck ACT-02`,
      });
    }
    return findings;
  },
};
