import type { GuardedHttpClient, GuardedResponse } from './guarded-client';
import type { Framework, ScriptFile, SurfaceMap } from './surface';

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

  const pages = new Set<string>([home.url]);
  const scriptUrls = new Set<string>();
  const queue: { url: URL; depth: number; html: string }[] = [{ url: new URL(home.url), depth: 0, html: home.body }];
  let allHtml = home.body;

  for (let i = 0; i < queue.length && pages.size <= maxPages; i++) {
    const { url, depth, html } = queue[i]!;
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
  for (const s of scripts) for (const e of extractEndpoints(s.body, origin)) endpoints.add(e);

  return {
    origin,
    framework: detectFramework(allHtml),
    isDevServer: looksLikeDevServer(allHtml),
    pages: [...pages],
    scripts,
    endpoints: [...endpoints],
    home: { url: home.url, status: home.status, headers: home.headers, body: home.body },
  };
}
