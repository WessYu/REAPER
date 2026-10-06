import type {
  Category,
  Confidence,
  Finding,
  ScanResult,
  Severity,
} from "./model.js";

export interface SecurityScore {
  overall: number;
  provisional: boolean;
  categories: Record<Category, number>;
  activeFindings: number;
  capReason?: string;
}

const categories: Category[] = [
  "Authorization",
  "SQL Safety",
  "Tenant Isolation",
  "RLS",
  "Privileges",
  "Supabase",
  "Migrations",
  "Secrets & Crypto",
];

const severityPenalty: Record<Severity, number> = {
  CRITICAL: 45,
  HIGH: 25,
  MEDIUM: 12,
  LOW: 5,
  INFO: 1,
};

const confidenceWeight: Record<Confidence, number> = {
  CONFIRMED: 1.5,
  HIGH: 1.15,
  MEDIUM: 1,
  LOW: 0.6,
};

function findingPenalty(finding: Finding): number {
  return (
    severityPenalty[finding.severity] * confidenceWeight[finding.confidence]
  );
}

export function calculateScore(result: ScanResult): SecurityScore {
  const active = result.findings.filter(
    (finding) => finding.status !== "suppressed",
  );
  const byCategory = Object.fromEntries(
    categories.map((category) => {
      const penalty = active
        .filter((finding) => finding.category === category)
        .reduce((sum, finding) => sum + findingPenalty(finding), 0);
      return [category, Math.max(0, Math.round(100 - penalty))];
    }),
  ) as Record<Category, number>;

  let overall = Math.round(
    Object.values(byCategory).reduce((sum, value) => sum + value, 0) /
      categories.length,
  );
  let capReason: string | undefined;
  const has = (severity: Severity, confidence?: Confidence) =>
    active.some(
      (finding) =>
        finding.severity === severity &&
        (confidence === undefined || finding.confidence === confidence),
    );

  if (has("CRITICAL", "CONFIRMED")) {
    overall = Math.min(overall, 20);
    capReason = "Confirmed critical finding caps the overall score at 20.";
  } else if (has("CRITICAL")) {
    overall = Math.min(overall, 35);
    capReason = "Critical finding caps the overall score at 35.";
  } else if (has("HIGH")) {
    overall = Math.min(overall, 70);
    capReason = "High-severity finding caps the overall score at 70.";
  } else if (has("MEDIUM")) {
    overall = Math.min(overall, 85);
    capReason = "Medium-severity finding caps the overall score at 85.";
  } else if (has("LOW")) {
    overall = Math.min(overall, 95);
    capReason = "Low-severity finding caps the overall score at 95.";
  }

  return {
    overall,
    provisional:
      result.diagnostics.length > 0 ||
      (!result.coverage.source &&
        !result.coverage.database &&
        !result.coverage.runtime),
    categories: byCategory,
    activeFindings: active.length,
    capReason,
  };
}

export function renderScore(score: SecurityScore, format: string): string {
  if (format === "json") return JSON.stringify(score, null, 2) + "\n";
  const lines = [
    "REAPER Data Security Score: " +
      score.overall +
      "/100" +
      (score.provisional ? " (provisional)" : ""),
    "",
    ...Object.entries(score.categories).map(
      ([category, value]) => category.padEnd(20) + " " + value,
    ),
    "",
    "Active findings: " + score.activeFindings,
  ];
  if (score.capReason) lines.push(score.capReason);
  lines.push(
    "Score is an explainable triage aid, not proof that an application is secure.",
  );
  if (format === "terminal") return lines.join("\n") + "\n";
  if (format === "markdown")
    return (
      "# REAPER Data Security Score\n\n\x60\x60\x60text\n" +
      lines.join("\n") +
      "\n\x60\x60\x60\n"
    );
  throw new Error("Score format must be terminal, json or markdown.");
}
