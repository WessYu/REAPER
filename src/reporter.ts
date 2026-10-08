import { severities, type Finding, type ScanResult } from "./model.js";
export function report(result: ScanResult, format: string): string {
  if (format === "json") return JSON.stringify(result, null, 2) + "\n";
  if (format === "sarif")
    return (
      JSON.stringify(
        {
          $schema: "https://json.schemastore.org/sarif-2.1.0.json",
          version: "2.1.0",
          runs: [
            {
              tool: {
                driver: {
                  name: "REAPER",
                  version: result.version,
                  rules: [
                    ...new Map(
                      result.findings.map((f) => [
                        f.ruleId,
                        {
                          id: f.ruleId,
                          shortDescription: { text: f.title },
                          help: { text: f.recommendation },
                        },
                      ]),
                    ).values(),
                  ],
                },
              },
              results: result.findings
                .filter((f) => f.status !== "suppressed")
                .map((f) => ({
                  ruleId: f.ruleId,
                  level: ["HIGH", "CRITICAL"].includes(f.severity)
                    ? "error"
                    : f.severity === "INFO"
                      ? "note"
                      : "warning",
                  message: { text: f.description },
                  locations: [
                    {
                      physicalLocation: {
                        artifactLocation: {
                          uri: f.file
                            .split("/")
                            .map(encodeURIComponent)
                            .join("/"),
                        },
                        region: { startLine: f.line, startColumn: f.column },
                      },
                    },
                  ],
                  partialFingerprints: { "reaper/v1": f.fingerprint },
                  baselineState: f.status === "baseline" ? "unchanged" : "new",
                  ...(f.dataFlow.length
                    ? {
                        codeFlows: [
                          {
                            threadFlows: [
                              {
                                locations: f.dataFlow.map((e) => ({
                                  location: {
                                    physicalLocation: {
                                      artifactLocation: {
                                        uri: e.file
                                          .split("/")
                                          .map(encodeURIComponent)
                                          .join("/"),
                                      },
                                      region: {
                                        startLine: e.line,
                                        startColumn: e.column,
                                      },
                                    },
                                    message: { text: e.label },
                                  },
                                })),
                              },
                            ],
                          },
                        ],
                      }
                    : {}),
                })),
              invocations: [
                {
                  executionSuccessful: result.diagnostics.length === 0,
                  toolExecutionNotifications: result.diagnostics.map((d) => ({
                    level: "warning",
                    message: { text: d.message },
                  })),
                },
              ],
            },
          ],
        },
        null,
        2,
      ) + "\n"
    );
  const active = result.findings.filter((f) => f.status === "new");
  const lines = [
    `REAPER ${result.version} — Data Access Security Engine`,
    `${result.metrics.files} files | ${result.metrics.routes} routes | ${result.metrics.sinks} sinks | ${result.metrics.durationMs} ms`,
    severities
      .map((s) => `${s}: ${active.filter((f) => f.severity === s).length}`)
      .join(" | "),
    "",
  ];
  for (const f of result.findings)
    lines.push(
      `${f.severity} ${f.ruleId} [${f.confidence}; ${f.status}] ${f.file}:${f.line}`,
      `  ${f.title}`,
      `  ${f.description}`,
      `  Fix: ${f.recommendation}`,
      "",
    );
  for (const d of result.diagnostics)
    lines.push(`INCOMPLETE: ${d.file ?? ""} ${d.message}`);
  lines.push(
    result.coverage.runtime
      ? "Runtime findings reflect configured assertions; static/catalog findings remain review candidates, not proof of exploitability."
      : "Static/catalog findings are review candidates, not proof of exploitability. Runtime verification was not part of this report.",
  );
  if (format === "terminal") return lines.join("\n") + "\n";
  if (format === "markdown")
    return (
      "# REAPER report\n\n```text\n" +
      lines.join("\n").replaceAll("```", "~~~") +
      "\n```\n"
    );
  throw new Error(`Unsupported report format: ${format}`);
}
export function fails(findings: Finding[], threshold: string): boolean {
  const index = severities.indexOf(
    threshold.toUpperCase() as Finding["severity"],
  );
  if (index < 0)
    throw new Error("fail-on must be critical, high, medium, low or info.");
  return findings.some(
    (f) => f.status === "new" && severities.indexOf(f.severity) <= index,
  );
}
