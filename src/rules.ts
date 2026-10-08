import { finding } from "./findings.js";
import type { Config, Finding, ScanResult } from "./model.js";

export interface RuleContext {
  result: ScanResult;
  config: Config;
  add(input: Omit<Finding, "id" | "fingerprint" | "status">, identity: string): Finding;
}

export interface ReaperRule {
  id: string;
  run(context: RuleContext): void | Promise<void>;
}

export async function runRules(
  result: ScanResult,
  config: Config,
  rules: ReaperRule[],
): Promise<void> {
  const seen = new Set<string>();
  for (const rule of rules) {
    if (!/^REAPER-[A-Z0-9-]+$/.test(rule.id))
      throw new Error(`Invalid custom rule id: ${rule.id}`);
    if (seen.has(rule.id)) throw new Error(`Duplicate custom rule id: ${rule.id}`);
    seen.add(rule.id);
    const context: RuleContext = {
      result,
      config,
      add(input, identity) {
        if (input.ruleId !== rule.id)
          throw new Error(
            `Rule ${rule.id} attempted to emit finding ${input.ruleId}.`,
          );
        const emitted = finding(input, `custom:${rule.id}:${identity}`);
        result.findings.push(emitted);
        return emitted;
      },
    };
    await rule.run(context);
  }
}
