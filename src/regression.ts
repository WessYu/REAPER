import type { AttackConfig, Config, ScanResult } from "./model.js";
import { validateAttackConfig } from "./attack-config.js";

function js(value: unknown): string {
  return JSON.stringify(value, null, 2)
    .replaceAll("<", "\\u003c")
    .replaceAll(">", "\\u003e");
}

export function renderAttackRegression(
  configValue: Config | AttackConfig,
  result: ScanResult,
): string {
  if (!result.attack)
    throw new Error("Regression generation requires an active attack report.");
  const config =
    "scope" in configValue
      ? validateAttackConfig(configValue)
      : validateAttackConfig(configValue.attack);
  const confirmed = new Set(
    result.attack.scenarios
      .filter((scenario) => scenario.status === "confirmed")
      .map((scenario) => scenario.name),
  );
  if (!confirmed.size)
    throw new Error("Attack report contains no confirmed scenarios.");
  const scenarios = config.scenarios.filter((scenario) =>
    confirmed.has(scenario.name),
  );
  if (scenarios.length !== confirmed.size)
    throw new Error(
      "Attack config no longer contains every confirmed scenario from the report.",
    );

  const regressionConfig: Config = {
    attack: {
      ...config,
      scenarios,
    },
  };
  const names = scenarios.map((scenario) => scenario.name).join(", ");
  return `import test from "node:test";
import assert from "node:assert/strict";
import { attack } from "@wess2001/reaper";

const target = process.env.REAPER_ATTACK_TARGET;
if (!target)
  throw new Error("REAPER_ATTACK_TARGET is required for active security regression tests.");

const config = ${js(regressionConfig)};

test("REAPER active-security regression: ${names.replaceAll('"', '\\"')}", async () => {
  const result = await attack(target, config);
  const confirmed = result.findings.filter(
    (finding) =>
      finding.status === "new" &&
      finding.confidence === "CONFIRMED" &&
      finding.category === "Active Security",
  );
  assert.equal(
    confirmed.length,
    0,
    confirmed
      .map((finding) =>
        finding.ruleId + ": " + finding.title + " [" + (finding.route ?? "runtime") + "]",
      )
      .join("\\n"),
  );
});
`;
}
