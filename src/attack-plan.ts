import type { AttackConfig, Finding, ScanResult } from "./model.js";

export interface AttackPlanCandidate {
  sourceFindingId: string;
  kind: "bola" | "tenant" | "authorization";
  method?: string;
  pathTemplate?: string;
  resource?: string;
  severity: Finding["severity"];
  confidence: Finding["confidence"];
  reason: string;
  prerequisites: string[];
}

export interface AttackPlan {
  version: 1;
  sourceVersion: ScanResult["version"];
  candidates: AttackPlanCandidate[];
}

function routeParts(
  route: string | undefined,
): { method?: string; pathTemplate?: string } {
  if (!route) return {};
  const match = route.match(/^([A-Z]+)\s+(.+)$/);
  if (!match) return { pathTemplate: route };
  const method = match[1];
  let pathTemplate = match[2];
  pathTemplate = pathTemplate
    .replace(/:([A-Za-z_][A-Za-z0-9_]*)/g, (_all, name: string) =>
      /(?:id|uuid|key)$/i.test(name)
        ? "{{RESOURCE_ID}}"
        : `{{${name.toUpperCase()}}}`,
    )
    .replace(/\[([A-Za-z_][A-Za-z0-9_]*)\]/g, (_all, name: string) =>
      /(?:id|uuid|key)$/i.test(name)
        ? "{{RESOURCE_ID}}"
        : `{{${name.toUpperCase()}}}`,
    );
  return { method, pathTemplate };
}

function candidate(finding: Finding): AttackPlanCandidate | undefined {
  if (finding.status === "suppressed") return undefined;
  const route = routeParts(finding.route);
  if (finding.ruleId === "REAPER-AUTH-001")
    return {
      sourceFindingId: finding.id,
      kind: "bola",
      ...route,
      resource: finding.resource,
      severity: finding.severity,
      confidence: finding.confidence,
      reason:
        "Static analysis observed request-dependent data access without a proven ownership constraint.",
      prerequisites: [
        "two authorized synthetic users",
        "a resource created or owned by the second user",
        "a safe cleanup path for synthetic state",
      ],
    };
  if (finding.ruleId === "REAPER-TENANT-001")
    return {
      sourceFindingId: finding.id,
      kind: "tenant",
      ...route,
      resource: finding.resource,
      severity: finding.severity,
      confidence: finding.confidence,
      reason:
        "Static analysis observed tenant-scoped access without a proven tenant constraint.",
      prerequisites: [
        "two authorized synthetic identities in different tenants",
        "a resource belonging to the owner tenant",
        "a safe cleanup path for synthetic state",
      ],
    };
  if (
    finding.category === "Authorization" &&
    finding.route &&
    finding.confidence !== "LOW"
  )
    return {
      sourceFindingId: finding.id,
      kind: "authorization",
      ...route,
      resource: finding.resource,
      severity: finding.severity,
      confidence: finding.confidence,
      reason:
        "Authorization evidence is suitable for an operator-defined runtime denial assertion.",
      prerequisites: [
        "an identity that should be denied",
        "an explicit expected denial status",
      ],
    };
  return undefined;
}

export function buildAttackPlan(result: ScanResult): AttackPlan {
  const candidates = result.findings
    .map(candidate)
    .filter((item): item is AttackPlanCandidate => item !== undefined)
    .sort(
      (a, b) =>
        a.kind.localeCompare(b.kind) ||
        (a.pathTemplate ?? "").localeCompare(b.pathTemplate ?? "") ||
        a.sourceFindingId.localeCompare(b.sourceFindingId),
    );
  return { version: 1, sourceVersion: result.version, candidates };
}

export interface IdentityMatrixEntry {
  attacker: string;
  owner: string;
  dimensions: Array<"ownership" | "tenant">;
}

export function buildIdentityMatrix(config: AttackConfig): IdentityMatrixEntry[] {
  const entries: IdentityMatrixEntry[] = [];
  const identities = Object.entries(config.identities);
  for (const [attackerName, attacker] of identities)
    for (const [ownerName, owner] of identities) {
      if (attackerName === ownerName) continue;
      const dimensions: IdentityMatrixEntry["dimensions"] = [];
      if (
        attacker.role === owner.role ||
        (attacker.role === undefined && owner.role === undefined)
      )
        dimensions.push("ownership");
      if (
        attacker.tenant !== undefined &&
        owner.tenant !== undefined &&
        attacker.tenant !== owner.tenant
      )
        dimensions.push("tenant");
      if (dimensions.length)
        entries.push({
          attacker: attackerName,
          owner: ownerName,
          dimensions,
        });
    }
  return entries.sort(
    (a, b) =>
      a.attacker.localeCompare(b.attacker) || a.owner.localeCompare(b.owner),
  );
}
