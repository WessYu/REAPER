import type { ScanResult } from "./model.js";
import { calculateScore } from "./score.js";

function escapeHtml(value: unknown): string {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function renderDashboard(result: ScanResult): string {
  const score = calculateScore(result);
  const counts = new Map<string, number>();
  for (const finding of result.findings)
    counts.set(finding.severity, (counts.get(finding.severity) ?? 0) + 1);
  const rows = result.findings
    .map(
      (finding) => `<tr>
<td><strong>${escapeHtml(finding.severity)}</strong></td>
<td><code>${escapeHtml(finding.ruleId)}</code></td>
<td>${escapeHtml(finding.title)}</td>
<td>${escapeHtml(finding.route ?? "—")}</td>
<td>${escapeHtml(finding.resource ?? "—")}</td>
<td><code>${escapeHtml(`${finding.file}:${finding.line}`)}</code></td>
</tr>`,
    )
    .join("");
  const graph = result.graph.edges
    .map((edge) => `<li><code>${escapeHtml(edge.from)}</code> → <code>${escapeHtml(edge.to)}</code> <small>${escapeHtml(edge.relation)}</small></li>`)
    .join("");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>REAPER Security Dashboard</title>
<style>
:root{color-scheme:dark;background:#0b0b0b;color:#ededed;font-family:Inter,ui-sans-serif,system-ui,sans-serif}
body{margin:0;padding:32px;max-width:1440px;margin-inline:auto}h1{letter-spacing:.08em}p{color:#aaa}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:24px 0}
.card{border:1px solid #303030;background:#111;border-radius:14px;padding:18px}
.value{font-size:2rem;font-weight:750}.muted{color:#888}table{width:100%;border-collapse:collapse;background:#111;border:1px solid #303030}
th,td{text-align:left;padding:12px;border-bottom:1px solid #282828;vertical-align:top}th{color:#aaa;font-size:.8rem;text-transform:uppercase}
code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}section{margin-top:32px}ul{line-height:1.7;padding-left:22px}
</style>
</head>
<body>
<h1>REAPER</h1>
<p>Data Access Security Engine · report ${escapeHtml(result.version)}</p>
<div class="grid">
<div class="card"><div class="muted">Security score</div><div class="value">${escapeHtml(score.score)}</div></div>
<div class="card"><div class="muted">Findings</div><div class="value">${result.findings.length}</div></div>
<div class="card"><div class="muted">Critical</div><div class="value">${counts.get("CRITICAL") ?? 0}</div></div>
<div class="card"><div class="muted">High</div><div class="value">${counts.get("HIGH") ?? 0}</div></div>
<div class="card"><div class="muted">Routes</div><div class="value">${result.metrics.routes}</div></div>
<div class="card"><div class="muted">Data sinks</div><div class="value">${result.metrics.sinks}</div></div>
</div>
<section><h2>Findings</h2><table><thead><tr><th>Severity</th><th>Rule</th><th>Finding</th><th>Route</th><th>Resource</th><th>Location</th></tr></thead><tbody>${rows || '<tr><td colspan="6">No findings.</td></tr>'}</tbody></table></section>
<section><h2>Observed access graph</h2><ul>${graph || "<li>No graph edges.</li>"}</ul></section>
</body>
</html>\n`;
}
