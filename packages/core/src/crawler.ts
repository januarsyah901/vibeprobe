import type { GuardedHttpClient, GuardedResponse } from './guarded-client';
import type { Framework, FormInfo, ParamInfo, ScriptFile, SurfaceMap, WriteEndpoint } from './surface';

export interface CrawlOptions {
  maxPages?: number;
  maxDepth?: number;
  maxScripts?: number;
}

const ATTR_RE = /\b(?:href|src|action)\s*=\s*["']([^"'#]+)["']/gi;
const SCRIPT_SRC_RE = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi;
const ENDPOINT_RES = [
  /\b(?:fetch|axios(?:\.\w+)?|\$http\.\w+|ky(?:\.\w+)?)\(\s*[`"'](\/[^`"'\s$]*|https?:\/\/[^`"'\s$]*)[`"']/g,
  /[`"'](\/api\/[A-Za-z0-9_\-./]*)[`"']/g,
];

const FORM_RE = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
const FIELD_RE = /<(?:input|textarea|select)\b[^>]*\bname\s*=\s*["']([^"']+)["']/gi;
const attr = (tag: string, name: string) => new RegExp(`\\b${name}\\s*=\\s*["']([^"']*)["']`, 'i').exec(tag)?.[1];
const WRITE_FETCH_RE = /\bfetch\(\s*[`"'](\/[^`"'\s$?]*)[`"']\s*,\s*\{[^}]*?\bmethod\s*:\s*[`"'](POST|PUT|PATCH)[`"']/gi;
const WRITE_AXIOS_RE = /\baxios\.(post|put|patch)\(\s*[`"'](\/[^`"'\s$?]*)[`"']/gi;
const PARAM_STRING_RE = /[`"'](\/[A-Za-z0-9_\-./]+)\?([^`"'\s]*)/g;

export function extractForms(html: string, page: URL): FormInfo[] {
  const forms: FormInfo[] = [];
  for (const m of html.matchAll(FORM_RE)) {
    const action = new URL(attr(m[1]!, 'action') || page.pathname, page);
    if (action.origin !== page.origin) continue;
    const method = (attr(m[1]!, 'method') ?? 'GET').toUpperCase() === 'POST' ? 'POST' : 'GET';
    const fields = [...new Set([...m[2]!.matchAll(FIELD_RE)].map((f) => f[1]!))];
    forms.push({ action: action.origin + action.pathname, method, fields, page: page.href });
  }
  return forms;
}

/** Query parameters named in links and in JavaScript strings such as "/search?q=". */
export function extractParams(source: string, origin: string): ParamInfo[] {
  const found = new Map<string, ParamInfo>();
  for (const m of source.matchAll(PARAM_STRING_RE)) {
    for (const piece of m[2]!.split('&')) {
      const name = /^[A-Za-z0-9_\-[\]]+(?==|$)/.exec(piece)?.[0];
      if (!name) continue;
      const url = new URL(m[1]!, origin).href;
      found.set(`${url}|${name}`, { url, name });
    }
  }
  return [...found.values()];
}

export function extractWriteEndpoints(js: string, origin: string): WriteEndpoint[] {
  const found = new Map<string, WriteEndpoint>();
  const add = (path: string, method: string) => {
    try {
      const u = new URL(path, origin);
      if (u.origin === origin) found.set(`${method}|${u.pathname}`, { url: u.origin + u.pathname, method: method.toUpperCase() as WriteEndpoint['method'] });
    } catch {
      /* ignore malformed */
    }
  };
  for (const m of js.matchAll(WRITE_FETCH_RE)) add(m[1]!, m[2]!.toUpperCase());
  for (const m of js.matchAll(WRITE_AXIOS_RE)) add(m[2]!, m[1]!.toUpperCase());
  return [...found.values()];
}

export function detectFramework(html: string): Framework {
  if (/\/_next\//.test(html)) return 'nextjs';
  if (/\/@vite\/client|type=["']module["'][^>]*src=["']\/src\//.test(html)) return 'vite';
  return 'unknown';
}

export function looksLikeDevServer(html: string): boolean {
  return /\/@vite\/client|\/_next\/webpack-hmr|webpack-dev-server|\/__nextjs_original-stack|react-refresh/.test(html);
}

export function extractEndpoints(js: string, origin: string): string[] {
  const found = new Set<string>();
  for (const re of ENDPOINT_RES) {
    for (const m of js.matchAll(re)) {
      try {
        const u = new URL(m[1]!, origin);
        if (u.origin === origin) found.add(u.origin + u.pathname);
      } catch {
        /* ignore malformed */
      }
    }
  }
  return [...found];
}

function sameOrigin(raw: string, base: URL): URL | undefined {
  try {
    const u = new URL(raw, base);
    u.hash = '';
    return u.origin === base.origin && /^https?:$/.test(u.protocol) ? u : undefined;
  } catch {
    return undefined;
  }
}

const isHtml = (r: GuardedResponse) => (r.headers.get('content-type') ?? '').includes('text/html');

/** Layer 1 of F3: fetch HTML, follow same-origin links, download scripts, mine endpoints. */
export async function crawl(
  client: GuardedHttpClient,
  start: URL,
  options: CrawlOptions = {},
): Promise<SurfaceMap> {
  const maxPages = options.maxPages ?? 30;
  const maxDepth = options.maxDepth ?? 2;
  const maxScripts = options.maxScripts ?? 40;

  const home = await client.request(start);
  const origin = new URL(home.url).origin;

  const forms: FormInfo[] = [];
  const params = new Map<string, ParamInfo>();
  const addParams = (list: ParamInfo[]) => list.forEach((p) => params.set(`${p.url}|${p.name}`, p));
  const pages = new Set<string>([home.url]);
  const scriptUrls = new Set<string>();
  const queue: { url: URL; depth: number; html: string }[] = [{ url: new URL(home.url), depth: 0, html: home.body }];
  let allHtml = home.body;

  for (let i = 0; i < queue.length && pages.size <= maxPages; i++) {
    const { url, depth, html } = queue[i]!;
    forms.push(...extractForms(html, url));
    for (const m of html.matchAll(ATTR_RE)) {
      const u = sameOrigin(m[1]!, url);
      if (u) for (const name of new Set(u.searchParams.keys())) addParams([{ url: u.origin + u.pathname, name }]);
    }
    for (const m of html.matchAll(SCRIPT_SRC_RE)) {
      const u = sameOrigin(m[1]!, url);
      if (u) scriptUrls.add(u.href);
    }
    if (depth >= maxDepth) continue;
    for (const m of html.matchAll(ATTR_RE)) {
      const u = sameOrigin(m[1]!, url);
      if (!u || /\.(js|mjs|css|map|png|jpe?g|gif|svg|ico|woff2?|ttf|webp|pdf)$/i.test(u.pathname)) continue;
      if (pages.has(u.href) || pages.size >= maxPages) continue;
      try {
        const res = await client.request(u);
        if (res.status === 200 && isHtml(res)) {
          pages.add(u.href);
          allHtml += res.body;
          queue.push({ url: u, depth: depth + 1, html: res.body });
        }
      } catch {
        /* an unreachable link is not fatal */
      }
    }
  }

  const scripts: ScriptFile[] = [];
  for (const url of [...scriptUrls].slice(0, maxScripts)) {
    try {
      const res = await client.request(url);
      if (res.status === 200) scripts.push({ url, body: res.body });
    } catch {
      /* skip */
    }
  }

  const endpoints = new Set<string>();
  const writes = new Map<string, WriteEndpoint>();
  for (const s of scripts) {
    for (const e of extractEndpoints(s.body, origin)) endpoints.add(e);
    addParams(extractParams(s.body, origin));
    for (const w of extractWriteEndpoints(s.body, origin)) writes.set(`${w.method}|${w.url}`, w);
  }
  for (const f of forms) if (f.method === 'POST') writes.set(`POST|${f.action}`, { url: f.action, method: 'POST' });
  for (const f of forms) if (f.method === 'GET') for (const name of f.fields) addParams([{ url: f.action, name }]);

  return {
    origin,
    framework: detectFramework(allHtml),
    isDevServer: looksLikeDevServer(allHtml),
    pages: [...pages],
    scripts,
    endpoints: [...endpoints],
    forms,
    params: [...params.values()],
    writeEndpoints: [...writes.values()],
    home: { url: home.url, status: home.status, headers: home.headers, body: home.body },
  };
}
