import type { Finding, Severity } from '@vibeprobe/core';

export interface HtmlMeta {
  target: string;
  version: string;
  generatedAt: Date;
}

export function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];

const CSS = `
:root{--bg:#f6f8fa;--card:#fff;--text:#1f2328;--muted:#59636e;--border:#d1d9e0;--code:#f0f3f6;--accent:#0969da;
--critical:#cf222e;--high:#bc4c00;--medium:#9a6700;--low:#0550ae}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--card:#161b22;--text:#e6edf3;--muted:#9198a1;--border:#30363d;--code:#0d1117;--accent:#4493f8;
--critical:#ff7b72;--high:#ffa657;--medium:#e3b341;--low:#79c0ff}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:860px;margin:0 auto;padding:32px 16px 64px}
h1{margin:0 0 4px;font-size:28px}h2{margin:36px 0 12px;font-size:20px}
.muted{color:var(--muted)}.meta{margin:0 0 20px;font-size:14px;color:var(--muted)}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 8px;padding:0;list-style:none}
.chip{padding:2px 10px;border:1px solid var(--border);border-radius:999px;font-size:14px;background:var(--card)}
.sev{font-weight:700;text-transform:uppercase;font-size:12px;letter-spacing:.04em}
.sev.critical{color:var(--critical)}.sev.high{color:var(--high)}.sev.medium{color:var(--medium)}.sev.low{color:var(--low)}
.first{border:1px solid var(--border);border-left:4px solid var(--critical);border-radius:8px;background:var(--card);padding:4px 20px 12px}
.first ol{margin:8px 0 0;padding-left:22px}.first li{margin:6px 0}
a{color:var(--accent)}
article{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:16px 20px;margin:14px 0}
article h3{margin:2px 0 6px;font-size:18px}
.sub{font-size:13px;color:var(--muted);margin:0 0 10px;word-break:break-all}
article h4{margin:16px 0 6px;font-size:13px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
pre{margin:0;padding:12px;background:var(--code);border:1px solid var(--border);border-radius:6px;overflow-x:auto;white-space:pre-wrap;word-break:break-word;font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.row{display:flex;justify-content:space-between;align-items:center;gap:8px}
button{font:inherit;font-size:13px;padding:3px 10px;border:1px solid var(--border);border-radius:6px;background:var(--card);color:var(--text);cursor:pointer}
button:hover{border-color:var(--accent)}button:focus-visible,a:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.clean{padding:24px;border:1px solid var(--border);border-radius:8px;background:var(--card);text-align:center}
footer{margin-top:40px;font-size:13px;color:var(--muted)}
`;

const JS = `
document.addEventListener('click',function(e){
  var b=e.target.closest('button[data-copy]');if(!b)return;
  var pre=document.getElementById(b.getAttribute('data-copy'));if(!pre)return;
  var text=pre.textContent,done=function(){var o=b.textContent;b.textContent='Copied';setTimeout(function(){b.textContent=o},1500)};
  if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(text).then(done,function(){});return}
  var t=document.createElement('textarea');t.value=text;t.style.position='fixed';t.style.opacity='0';document.body.appendChild(t);t.select();
  try{document.execCommand('copy');done()}catch(_){}document.body.removeChild(t);
});
`;

function finding(f: Finding, id: string): string {
  return `<article id="${id}">
<span class="sev ${f.severity}">${f.severity}</span> <span class="muted">· ${escapeHtml(f.checkId)} · confidence ${f.confidence}</span>
<h3>${escapeHtml(f.title)}</h3>
<p class="sub">${escapeHtml(f.url)}</p>
<p>${escapeHtml(f.why)}</p>
<h4>Evidence</h4>
<pre>${escapeHtml(f.evidence.request)}${f.evidence.status !== undefined ? ` → ${f.evidence.status}` : ''}\n${escapeHtml(f.evidence.excerpt)}</pre>
<h4>Reproduce (read-only)</h4>
<pre>${escapeHtml(f.reproduce)}</pre>
<div class="row"><h4>Fix prompt: paste into your AI coding tool</h4><button type="button" data-copy="${id}-fix">Copy</button></div>
<pre id="${id}-fix">${escapeHtml(f.fixPrompt)}</pre>
</article>`;
}

/** One self-contained file: inline CSS and JS, no external requests, light and dark. */
export function toHtml(all: Finding[], meta: HtmlMeta): string {
  const main = all.filter((f) => f.confidence !== 'low');
  const low = all.filter((f) => f.confidence === 'low');
  const ids = new Map<Finding, string>([...main, ...low].map((f, i) => [f, `f${i + 1}`]));
  const top = main.filter((f) => f.confidence === 'high').slice(0, 3);
  const chips = SEVERITIES.map((s) => [s, main.filter((f) => f.severity === s).length] as const)
    .filter(([, n]) => n > 0)
    .map(([s, n]) => `<li class="chip"><span class="sev ${s}">${s}</span> ${n}</li>`)
    .join('');
  const when = meta.generatedAt.toISOString().slice(0, 16).replace('T', ' ') + ' UTC';

  const body: string[] = [
    `<h1>vibeprobe report</h1>`,
    `<p class="meta">Target <strong>${escapeHtml(meta.target)}</strong> · ${escapeHtml(when)} · vibeprobe ${escapeHtml(meta.version)}</p>`,
  ];
  if (main.length === 0) {
    body.push(`<div class="clean"><strong>No findings.</strong><br><span class="muted">Nothing proven wrong on the checks that ran.</span></div>`);
  } else {
    body.push(`<ul class="chips" aria-label="Findings by severity">${chips}</ul>`);
    if (top.length > 0) {
      body.push(
        `<section class="first" aria-labelledby="first"><h2 id="first">Fix these first</h2><ol>` +
          top.map((f) => `<li><a href="#${ids.get(f)}">${escapeHtml(f.title)}</a> <span class="muted">(${escapeHtml(f.checkId)}, ${f.severity})</span></li>`).join('') +
          `</ol></section>`,
      );
    }
    body.push(`<h2>All findings</h2>`, ...main.map((f) => finding(f, ids.get(f)!)));
  }
  if (low.length > 0) {
    body.push(
      `<h2>Needs a human look</h2><p class="muted">Low confidence: vibeprobe could not prove these. They do not fail CI. Check whether they are intended.</p>`,
      ...low.map((f) => finding(f, ids.get(f)!)),
    );
  }
  body.push(`<footer>Generated locally by vibeprobe. Nothing was sent anywhere. Secrets are masked.</footer>`);

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>vibeprobe report: ${escapeHtml(meta.target)}</title>
<style>${CSS}</style>
</head>
<body>
<main>
${body.join('\n')}
</main>
<script>${JS}</script>
</body>
</html>
`;
}
