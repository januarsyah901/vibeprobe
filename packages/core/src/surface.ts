export type Framework = 'nextjs' | 'vite' | 'unknown';

export interface ScriptFile {
  url: string;
  body: string;
}

/** The "map" of the app that checks read from (PRD F3). */
export interface SurfaceMap {
  origin: string;
  framework: Framework;
  /** True when the target looks like a dev server (HMR client, dev overlay). */
  isDevServer: boolean;
  pages: string[];
  scripts: ScriptFile[];
  /** Same-origin endpoints found in JavaScript, as absolute URLs. */
  endpoints: string[];
  /** Headers and body of the start page. */
  home: { url: string; status: number; headers: Headers; body: string };
}
