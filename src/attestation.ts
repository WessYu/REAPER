import {
  createPrivateKey,
  createPublicKey,
  createHash,
  sign,
  verify,
} from "node:crypto";
import type { ScanResult } from "./model.js";

export interface ReportAttestation {
  format: "reaper-attestation-v1";
  reportVersion: ScanResult["version"];
  createdAt: string;
  digest: {
    algorithm: "sha256";
    value: string;
  };
  signature: {
    algorithm: "ed25519";
    value: string;
  };
}

function canonicalValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, entry]) => [key, canonicalValue(entry)]),
    );
  }
  return value;
}

export function canonicalReport(result: ScanResult): string {
  return JSON.stringify(canonicalValue(result));
}

export function reportDigest(result: ScanResult): string {
  return createHash("sha256").update(canonicalReport(result)).digest("hex");
}

function privateSigningKey(pem: string) {
  const key = createPrivateKey(pem);
  if (key.asymmetricKeyType !== "ed25519")
    throw new Error("Report signing requires an Ed25519 private key.");
  return key;
}

function publicSigningKey(pem: string) {
  const key = createPublicKey(pem);
  if (key.asymmetricKeyType !== "ed25519")
    throw new Error("Report verification requires an Ed25519 public key.");
  return key;
}

export function attestReport(
  result: ScanResult,
  privateKeyPem: string,
  createdAt = new Date().toISOString(),
): ReportAttestation {
  if (!Number.isFinite(Date.parse(createdAt)))
    throw new Error("Attestation createdAt must be an ISO-8601 date-time.");
  const canonical = canonicalReport(result);
  const signature = sign(null, Buffer.from(canonical), privateSigningKey(privateKeyPem));
  return {
    format: "reaper-attestation-v1",
    reportVersion: result.version,
    createdAt,
    digest: {
      algorithm: "sha256",
      value: createHash("sha256").update(canonical).digest("hex"),
    },
    signature: {
      algorithm: "ed25519",
      value: signature.toString("base64"),
    },
  };
}

export function validateAttestation(value: unknown): ReportAttestation {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("Invalid REAPER attestation.");
  const item = value as Record<string, unknown>;
  if (item.format !== "reaper-attestation-v1")
    throw new Error("Unsupported REAPER attestation format.");
  if (!["0.2.0"].includes(String(item.reportVersion)))
    throw new Error("Unsupported attested REAPER report version.");
  if (
    typeof item.createdAt !== "string" ||
    !Number.isFinite(Date.parse(item.createdAt))
  )
    throw new Error("Invalid attestation timestamp.");
  const digest = item.digest as Record<string, unknown> | undefined;
  if (
    !digest ||
    digest.algorithm !== "sha256" ||
    typeof digest.value !== "string" ||
    !/^[a-f0-9]{64}$/.test(digest.value)
  )
    throw new Error("Invalid attestation digest.");
  const signature = item.signature as Record<string, unknown> | undefined;
  if (
    !signature ||
    signature.algorithm !== "ed25519" ||
    typeof signature.value !== "string" ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(signature.value)
  )
    throw new Error("Invalid attestation signature.");
  return value as ReportAttestation;
}

export function verifyReportAttestation(
  result: ScanResult,
  value: unknown,
  publicKeyPem: string,
): boolean {
  const attestation = validateAttestation(value);
  if (attestation.reportVersion !== result.version) return false;
  const canonical = canonicalReport(result);
  const digest = createHash("sha256").update(canonical).digest("hex");
  if (digest !== attestation.digest.value) return false;
  return verify(
    null,
    Buffer.from(canonical),
    publicSigningKey(publicKeyPem),
    Buffer.from(attestation.signature.value, "base64"),
  );
}
