export type Framework = 'nextjs' | 'vite' | 'unknown';

export interface ScriptFile {
  url: string;
  body: string;
}

export interface FormInfo {
  /** Where the form sends data, as an absolute URL. */
  action: string;
  method: 'GET' | 'POST';
  fields: string[];
  /** The page the form was found on. */
  page: string;
}

/** A query parameter seen in a link or in JavaScript, e.g. /search?q= */
export interface ParamInfo {
  /** The endpoint without its query string. */
  url: string;
  name: string;
}

/** A same-origin endpoint the app calls with POST, PUT or PATCH. Only active checks send to these. */
export interface WriteEndpoint {
  url: string;
  method: 'POST' | 'PUT' | 'PATCH';
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
  forms: FormInfo[];
  params: ParamInfo[];
  writeEndpoints: WriteEndpoint[];
  /** Headers and body of the start page. */
  home: { url: string; status: number; headers: Headers; body: string };
}
