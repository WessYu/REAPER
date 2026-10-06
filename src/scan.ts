import path from "node:path";
import { readFile, realpath } from "node:fs/promises";
import { performance } from "node:perf_hooks";
import { analyze } from "./analysis.js";
import { discover, inferResources } from "./project.js";
import { readConfig, validateConfig } from "./config.js";
import type { Config, ScanResult } from "./model.js";
export async function scan(options: {
  root: string;
  config?: Config;
  configFile?: string;
  baseline?: string[];
}): Promise<ScanResult> {
  const start = performance.now();
  const root = await realpath(options.root);
  const config = options.configFile
    ? await readConfig(options.configFile)
    : validateConfig(options.config ?? {});
  const result: ScanResult = {
    version: "0.1.0",
    root,
    findings: [],
    diagnostics: [],
    graph: { nodes: [], edges: [] },
    metrics: { files: 0, routes: 0, sinks: 0, durationMs: 0, memoryBytes: 0 },
    coverage: { source: true, database: false, runtime: false },
  };
  const files = await discover(root, config, result.diagnostics);
  const resources = { ...(await inferResources(files)), ...config.resources };
  analyze(root, files, { ...config, resources }, result);
  const baseline = new Set(options.baseline ?? []);
  const contents = new Map<string, string[]>();
  for (const f of result.findings) {
    if (baseline.has(f.fingerprint)) f.status = "baseline";
    if (!contents.has(f.file))
      contents.set(
        f.file,
        (await readFile(path.join(root, f.file), "utf8")).split(/\r?\n/),
      );
    const previous = contents.get(f.file)?.[f.line - 2] ?? "";
    const match = previous.match(
      /^\s*\/\/\s*reaper-ignore\s+(REAPER-[A-Z]+-\d+)\s+--\s+reason:\s*(\S.*)$/,
    );
    if (match?.[1] === f.ruleId && match[2]!.trim().length >= 10) {
      f.status = "suppressed";
      f.suppression = match[2]!.trim();
    }
  }
  // Equivalent call contexts converge on one stable finding identity.
  result.findings = [
    ...new Map(result.findings.map((f) => [f.fingerprint, f])).values(),
  ].sort(
    (a, b) =>
      a.file.localeCompare(b.file) ||
      a.line - b.line ||
      a.ruleId.localeCompare(b.ruleId),
  );
  result.diagnostics = [
    ...new Map(result.diagnostics.map((d) => [JSON.stringify(d), d])).values(),
  ];
  result.metrics.files = files.filter((f) => !f.endsWith(".prisma")).length;
  result.metrics.durationMs = Math.round(performance.now() - start);
  result.metrics.memoryBytes = process.memoryUsage().rss;
  return result;
}
