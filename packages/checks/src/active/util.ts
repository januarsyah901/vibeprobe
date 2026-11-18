import { randomBytes } from 'node:crypto';
import { curlFor, curlWrite, type GuardedResponse, type HttpClient, type SurfaceMap, type WriteEndpoint } from '@vibeprobe/core';

/** A unique token for one probe, so a reflected value can only have come from our request. */
export const marker = (): string => 'vp' + randomBytes(4).toString('hex');

export interface Point {
  url: string;
  param: string;
  method: 'GET' | 'POST';
  /** Every field of the form, so the others can be filled with harmless values. */
  fields: string[];
}

const SKIP_FIELD = /^(csrf|_csrf|csrf_?token|authenticity_?token|_token|_method|submit|g-recaptcha-response)$/i;

/** Inputs worth testing: query parameters seen in links and scripts, and the fields of forms. */
export function injectionPoints(surface: SurfaceMap, limit = 12): Point[] {
  const found = new Map<string, Point>();
  for (const p of surface.params) {
    if (!SKIP_FIELD.test(p.name)) found.set(`GET|${p.url}|${p.name}`, { url: p.url, param: p.name, method: 'GET', fields: [p.name] });
  }
  for (const f of surface.forms) {
    for (const name of f.fields) {
      if (SKIP_FIELD.test(name)) continue;
      found.set(`${f.method}|${f.action}|${name}`, { url: f.action, param: name, method: f.method, fields: f.fields });
    }
  }
  return [...found.values()].slice(0, limit);
}

export interface Sent {
  res: GuardedResponse;
  /** "GET http://…/search?q=…" for the evidence. */
  request: string;
  curl: string;
}

/** Sends `value` in one input and a harmless "test" in the others. */
export async function sendInput(client: HttpClient, point: Point, value: string, headers: Record<string, string> = {}): Promise<Sent> {
  if (point.method === 'GET') {
    const u = new URL(point.url);
    for (const f of point.fields) u.searchParams.set(f, 'test');
    u.searchParams.set(point.param, value);
    const res = await client.request(u, { headers });
    return { res, request: `GET ${u.href}`, curl: curlFor(u.href, headers) };
  }
  const body = new URLSearchParams(Object.fromEntries(point.fields.map((f) => [f, 'test']))).toString();
  const params = new URLSearchParams(body);
  params.set(point.param, value);
  const payload = params.toString();
  const h = { 'content-type': 'application/x-www-form-urlencoded', ...headers };
  const res = await client.request(point.url, { method: 'POST', headers: h, body: payload });
  return { res, request: `POST ${point.url} body: ${payload}`, curl: curlWrite('POST', point.url, { headers: h, body: payload }) };
}

export async function sendJson(client: HttpClient, ep: Pick<WriteEndpoint, 'url' | 'method'>, body: unknown): Promise<Sent> {
  const payload = JSON.stringify(body);
  const headers = { 'content-type': 'application/json' };
  const res = await client.request(ep.url, { method: ep.method, headers, body: payload });
  return { res, request: `${ep.method} ${ep.url} body: ${payload}`, curl: curlWrite(ep.method, ep.url, { headers, body: payload }) };
}

export const isHtml = (res: GuardedResponse): boolean => (res.headers.get('content-type') ?? '').includes('text/html');
export const isJson = (res: GuardedResponse): boolean => (res.headers.get('content-type') ?? '').includes('json');
export const ok = (res: GuardedResponse): boolean => res.status >= 200 && res.status < 300;

/** Credentials-related endpoints: where attempt limits and injection into logins matter. */
export const LOGIN_PATH = /(login|signin|sign-in|auth\b|session|password|reset|forgot)/i;
/** Endpoints that are public on purpose, so "works without login" is expected there. */
export const PUBLIC_WRITE = /(login|signin|sign-in|signup|sign-up|register|contact|subscribe|newsletter|search|graphql|auth|session|token|password|reset|forgot|webhook|track|analytics|log\b|csp-report)/i;

/** Write endpoints that should need a login: everything except the public-by-design ones. */
export function protectedWrites(surface: SurfaceMap, limit = 8): WriteEndpoint[] {
  return surface.writeEndpoints.filter((e) => !PUBLIC_WRITE.test(new URL(e.url).pathname)).slice(0, limit);
}

export function loginEndpoints(surface: SurfaceMap, limit = 3): WriteEndpoint[] {
  return surface.writeEndpoints.filter((e) => LOGIN_PATH.test(new URL(e.url).pathname)).slice(0, limit);
}

export function parseJson(body: string): unknown {
  try {
    return JSON.parse(body);
  } catch {
    return undefined;
  }
}

export const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
