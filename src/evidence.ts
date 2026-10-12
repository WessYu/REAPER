import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";
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

export interface SignedEvidenceBundle {
  bundle: EvidenceBundle;
  signature: {
    algorithm: "ed25519";
    value: string;
    keyFingerprint: string;
  };
}

export interface SignedEvidenceVerification extends EvidenceVerification {
  signatureValid: boolean;
  keyFingerprint: string;
}

function fingerprintPublicKey(publicKeyPem: string): string {
  const key = createPublicKey(publicKeyPem);
  const der = key.export({ type: "spki", format: "der" });
  return createHash("sha256").update(der).digest("hex");
}

export function signEvidenceBundle(
  bundle: EvidenceBundle,
  privateKeyPem: string,
): SignedEvidenceBundle {
  const verified = verifyEvidenceBundle(bundle);
  if (!verified.valid)
    throw new Error("Cannot sign an evidence bundle with an invalid digest.");
  const privateKey = createPrivateKey(privateKeyPem);
  if (privateKey.asymmetricKeyType !== "ed25519")
    throw new Error("Evidence signing requires an Ed25519 private key.");
  const publicKey = createPublicKey(privateKey);
  const publicPem = publicKey
    .export({ type: "spki", format: "pem" })
    .toString();
  const signature = sign(
    null,
    Buffer.from(bundle.digest.value, "utf8"),
    privateKey,
  );
  return {
    bundle,
    signature: {
      algorithm: "ed25519",
      value: signature.toString("base64"),
      keyFingerprint: fingerprintPublicKey(publicPem),
    },
  };
}

export function verifySignedEvidence(
  value: unknown,
  publicKeyPem: string,
): SignedEvidenceVerification {
  if (!value || typeof value !== "object" || Array.isArray(value))
    return {
      valid: false,
      expected: "",
      observed: "",
      signatureValid: false,
      keyFingerprint: "",
    };
  const signed = value as Partial<SignedEvidenceBundle>;
  if (
    !signed.bundle ||
    signed.signature?.algorithm !== "ed25519" ||
    typeof signed.signature.value !== "string"
  )
    return {
      valid: false,
      expected: "",
      observed: "",
      signatureValid: false,
      keyFingerprint: "",
    };
  const integrity = verifyEvidenceBundle(signed.bundle);
  let signatureValid = false;
  let keyFingerprint = "";
  try {
    const publicKey = createPublicKey(publicKeyPem);
    if (publicKey.asymmetricKeyType !== "ed25519")
      throw new Error("not ed25519");
    keyFingerprint = fingerprintPublicKey(publicKeyPem);
    signatureValid = verify(
      null,
      Buffer.from(signed.bundle.digest.value, "utf8"),
      publicKey,
      Buffer.from(signed.signature.value, "base64"),
    );
  } catch {
    signatureValid = false;
  }
  return {
    ...integrity,
    valid:
      integrity.valid &&
      signatureValid &&
      signed.signature.keyFingerprint === keyFingerprint,
    signatureValid,
    keyFingerprint,
  };
}
