import { createHash } from "node:crypto";
import type { ScanResult } from "./model.js";

export interface EvidencePayload {
  schema: "reaper-evidence/v1";
  reportVersion: ScanResult["version"];
  root: string;
  coverage: ScanResult["coverage"];
  findings: ScanResult["findings"];
  graph: ScanResult["graph"];
  attack?: ScanResult["attack"];
}

export interface EvidenceBundle {
  payload: EvidencePayload;
  digest: {
    algorithm: "sha256";
    value: string;
  };
}

export interface EvidenceVerification {
  valid: boolean;
  expected: string;
  observed: string;
}

function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value))
    return "[" + value.map((item) => canonical(item)).join(",") + "]";
  const record = value as Record<string, unknown>;
  return (
    "{" +
    Object.keys(record)
      .sort()
      .filter((key) => record[key] !== undefined)
      .map((key) => JSON.stringify(key) + ":" + canonical(record[key]))
      .join(",") +
    "}"
  );
}

function digest(payload: EvidencePayload): string {
  return createHash("sha256").update(canonical(payload)).digest("hex");
}

export function buildEvidenceBundle(result: ScanResult): EvidenceBundle {
  const payload: EvidencePayload = {
    schema: "reaper-evidence/v1",
    reportVersion: result.version,
    root: result.root,
    coverage: { ...result.coverage },
    findings: result.findings.map((finding) => ({
      ...finding,
      evidence: [...finding.evidence],
      dataFlow: finding.dataFlow.map((entry) => ({ ...entry })),
    })),
    graph: {
      nodes: result.graph.nodes.map((node) => ({ ...node })),
      edges: result.graph.edges.map((edge) => ({ ...edge })),
    },
    attack: result.attack
      ? {
          ...result.attack,
          scenarios: result.attack.scenarios.map((scenario) => ({
            ...scenario,
          })),
          audit: result.attack.audit.map((event) => ({ ...event })),
        }
      : undefined,
  };
  return {
    payload,
    digest: { algorithm: "sha256", value: digest(payload) },
  };
}

export function verifyEvidenceBundle(value: unknown): EvidenceVerification {
  if (!value || typeof value !== "object" || Array.isArray(value))
    return { valid: false, expected: "", observed: "" };
  const bundle = value as Partial<EvidenceBundle>;
  if (
    !bundle.payload ||
    bundle.payload.schema !== "reaper-evidence/v1" ||
    bundle.digest?.algorithm !== "sha256" ||
    typeof bundle.digest.value !== "string"
  )
    return { valid: false, expected: "", observed: bundle.digest?.value ?? "" };
  const expected = digest(bundle.payload);
  return {
    valid: expected === bundle.digest.value,
    expected,
    observed: bundle.digest.value,
  };
}
