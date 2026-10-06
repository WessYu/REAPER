import { readFile } from "node:fs/promises";
import path from "node:path";
import { finding } from "./findings.js";
import type { Finding, ScanResult } from "./model.js";

function lineAt(source: string, offset: number): number {
  let line = 1;
  for (let index = 0; index < offset; index++)
    if (source.charCodeAt(index) === 10) line++;
  return line;
}

function normalizeIdentifier(value: string): string {
  return value.replace(/[",]/g, "").trim();
}

export async function analyzeMigrations(
  root: string,
  files: string[],
  result: ScanResult,
): Promise<void> {
  for (const file of files.filter((candidate) => candidate.endsWith(".sql"))) {
    const source = await readFile(file, "utf8");
    const relative = path.relative(root, file).split(path.sep).join("/");

    const add = (
      match: RegExpExecArray,
      ruleId: string,
      title: string,
      severity: Finding["severity"],
      resource: string,
      evidence: string[],
      recommendation: string,
    ) => {
      const line = lineAt(source, match.index);
      result.findings.push(
        finding(
          {
            file: relative,
            line,
            column: 1,
            ruleId,
            title,
            description: evidence.join(" "),
            severity,
            confidence: "HIGH",
            category: "Migrations",
            cwe: 284,
            resource,
            evidence,
            dataFlow: [],
            recommendation,
          },
          `${ruleId}:${relative}:${resource}:${match[0]
            .replace(/\s+/g, " ")
            .trim()
            .toLowerCase()}`,
        ),
      );
    };

    const disableRls =
      /ALTER\s+TABLE\s+(?:ONLY\s+)?([^\s;]+)\s+DISABLE\s+ROW\s+LEVEL\s+SECURITY\b/gi;
    for (const match of source.matchAll(disableRls)) {
      const resource = normalizeIdentifier(match[1]!);
      add(
        match,
        "REAPER-MIGRATION-001",
        "Migration disables row-level security",
        "HIGH",
        resource,
        [`RLS is disabled for ${resource}.`],
        "Keep RLS enabled for client-reachable tables or document and review the replacement authorization boundary before deployment.",
      );
    }

    const noForceRls =
      /ALTER\s+TABLE\s+(?:ONLY\s+)?([^\s;]+)\s+NO\s+FORCE\s+ROW\s+LEVEL\s+SECURITY\b/gi;
    for (const match of source.matchAll(noForceRls)) {
      const resource = normalizeIdentifier(match[1]!);
      add(
        match,
        "REAPER-MIGRATION-002",
        "Migration removes FORCE ROW LEVEL SECURITY",
        "MEDIUM",
        resource,
        [`FORCE ROW LEVEL SECURITY is removed from ${resource}.`],
        "Confirm that table owners are intended to bypass RLS before removing FORCE ROW LEVEL SECURITY.",
      );
    }

    const dropPolicy =
      /DROP\s+POLICY(?:\s+IF\s+EXISTS)?\s+([^\s;]+)(?:\s+ON\s+([^\s;]+))?/gi;
    for (const match of source.matchAll(dropPolicy)) {
      const policy = normalizeIdentifier(match[1]!);
      const resource = match[2]
        ? normalizeIdentifier(match[2])
        : `policy:${policy}`;
      add(
        match,
        "REAPER-MIGRATION-003",
        "Migration drops an RLS policy",
        "MEDIUM",
        resource,
        [`Policy ${policy} is dropped.`],
        "Review the replacement policy in the same deployment and verify that access does not become broader.",
      );
    }

    const grant =
      /GRANT\s+([^;]+?)\s+ON\s+(?:(TABLE|SCHEMA|FUNCTION)\s+)?([^\s;]+(?:\([^;]*?\))?)\s+TO\s+(PUBLIC|anon|authenticated)\b/gi;
    for (const match of source.matchAll(grant)) {
      const privileges = match[1]!
        .split(",")
        .map((value) => value.trim().toUpperCase());
      const role = match[4]!;
      const dangerous = privileges.some((value) =>
        [
          "ALL",
          "CREATE",
          "TRUNCATE",
          "TRIGGER",
          "REFERENCES",
          "EXECUTE",
        ].includes(value),
      );
      const broadDml =
        role.toUpperCase() === "PUBLIC" &&
        privileges.some((value) =>
          ["SELECT", "INSERT", "UPDATE", "DELETE"].includes(value),
        );
      if (!dangerous && !broadDml) continue;
      const resource = normalizeIdentifier(match[3]!);
      add(
        match,
        "REAPER-MIGRATION-004",
        "Migration grants broad database privileges",
        dangerous ? "HIGH" : "MEDIUM",
        resource,
        [
          `${role} receives ${privileges.join(", ")} on ${resource}.`,
          "Broad grants may be intentional, but they widen the database authorization boundary.",
        ],
        "Apply least privilege and prefer reviewed application roles/policies over PUBLIC or unnecessarily powerful client-role grants.",
      );
    }
  }
}
