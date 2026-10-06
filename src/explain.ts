import type { Finding } from "./model.js";

export function renderExplanation(finding: Finding, format: string): string {
  if (format === "json") return JSON.stringify(finding, null, 2) + "\n";
  const lines = [
    finding.id,
    "",
    "WHAT",
    finding.title,
    "",
    "WHERE",
    finding.file + ":" + finding.line + ":" + finding.column,
  ];
  if (finding.route) lines.push("Route: " + finding.route);
  if (finding.resource) lines.push("Resource: " + finding.resource);
  lines.push(
    "",
    "ASSESSMENT",
    "Severity: " + finding.severity,
    "Confidence: " + finding.confidence,
    "Status: " + finding.status,
    "",
    "WHY FLAGGED",
    ...finding.evidence.map((item) => "- " + item),
  );
  if (finding.dataFlow.length) {
    lines.push("", "DATA FLOW");
    for (const step of finding.dataFlow)
      lines.push(
        "- " +
          step.kind.toUpperCase() +
          " " +
          step.file +
          ":" +
          step.line +
          ":" +
          step.column +
          " — " +
          step.label,
      );
  }
  lines.push("", "REMEDIATION", finding.recommendation);
  if (finding.suppression) lines.push("", "SUPPRESSION", finding.suppression);

  if (format === "terminal") return lines.join("\n") + "\n";
  if (format === "markdown")
    return (
      "# " +
      finding.id +
      "\n\n" +
      lines
        .slice(2)
        .map((line) =>
          [
            "WHAT",
            "WHERE",
            "ASSESSMENT",
            "WHY FLAGGED",
            "DATA FLOW",
            "REMEDIATION",
            "SUPPRESSION",
          ].includes(line)
            ? "## " + line
            : line,
        )
        .join("\n") +
      "\n"
    );
  throw new Error("Explanation format must be terminal, json or markdown.");
}
