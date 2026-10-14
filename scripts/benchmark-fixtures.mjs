import { fileURLToPath, pathToFileURL } from "node:url";
import { scan } from "../dist/index.js";

const seededRules = ["REAPER-AUTH-001", "REAPER-SQL-001", "REAPER-TENANT-001"];

function proportion(numerator, denominator) {
  return denominator === 0 ? null : numerator / denominator;
}

export function confusionMetrics(cases) {
  const counts = { tp: 0, fp: 0, tn: 0, fn: 0 };
  for (const candidate of cases) {
    if (candidate.expected && candidate.observed) counts.tp++;
    else if (!candidate.expected && candidate.observed) counts.fp++;
    else if (candidate.expected && !candidate.observed) counts.fn++;
    else counts.tn++;
  }
  return {
    ...counts,
    precision: proportion(counts.tp, counts.tp + counts.fp),
    recall: proportion(counts.tp, counts.tp + counts.fn),
    specificity: proportion(counts.tn, counts.tn + counts.fp),
    sampleCount: cases.length,
  };
}

export async function benchmarkSeededFixtures() {
  const sets = [
    { fixture: "vulnerable", expected: true },
    { fixture: "secure", expected: false },
  ];
  const cases = [];
  const detail = [];
  for (const item of sets) {
    const root = fileURLToPath(
      new URL("../test/fixtures/" + item.fixture + "/", import.meta.url),
    );
    const result = await scan({ root });
    if (result.diagnostics.length)
      throw new Error("Benchmark scan was incomplete for " + item.fixture);
    const rules = new Set(
      result.findings
        .filter((finding) => finding.status !== "suppressed")
        .map((finding) => finding.ruleId),
    );
    for (const ruleId of seededRules) {
      cases.push({
        fixture: item.fixture,
        ruleId,
        expected: item.expected,
        observed: rules.has(ruleId),
      });
    }
    detail.push({
      fixture: item.fixture,
      fileCount: result.metrics.files,
      durationMs: result.metrics.durationMs,
      unlabeledFindings: result.findings.filter(
        (finding) => !seededRules.includes(finding.ruleId),
      ).length,
    });
  }
  return {
    benchmark: "REAPER seeded-fixtures v1",
    disclaimer:
      "Three planted rule families and one secure control fixture only; results cannot establish real-world scanner precision or commercial readiness.",
    ruleIds: seededRules,
    metrics: confusionMetrics(cases),
    detail,
  };
}

async function main() {
  const result = await benchmarkSeededFixtures();
  process.stdout.write(JSON.stringify(result, null, 2) + "\n");
  if (result.metrics.fp || result.metrics.fn) process.exitCode = 1;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  main().catch((error) => {
    console.error("Seeded detection benchmark failed: " + error.message);
    process.exitCode = 2;
  });
}
