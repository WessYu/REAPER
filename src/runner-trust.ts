import { createPublicKey } from "node:crypto";
import { InMemoryTrustStore, type TrustedPublicKey } from "./trust.js";

// Cloud Run reads this content from a mounted Secret Manager volume. It is
// never accepted from the execution envelope or a dispatcher-supplied key.
export const RUNNER_TRUST_FILE =
  "/var/run/reaper-trust/trusted-scope-keys.json";
export const RUNNER_TRUST_ENV = "REAPER_RUNNER_TRUSTED_SCOPE_KEYS_JSON";

function isRecord(value: unknown): value is Record<string, unknown> {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

export function parseRunnerTrustConfig(input: string): InMemoryTrustStore {
  if (
    typeof input !== "string" ||
    Buffer.byteLength(input, "utf8") > 65_536 ||
    input.trim().length === 0
  )
    throw new Error("Runner trust configuration is missing or oversized.");
  let raw: unknown;
  try {
    raw = JSON.parse(input);
  } catch {
    throw new Error("Runner trust configuration must be valid JSON.");
  }
  if (
    !isRecord(raw) ||
    Object.keys(raw).some((key) => !["version", "keys"].includes(key)) ||
    raw.version !== 1 ||
    !Array.isArray(raw.keys) ||
    raw.keys.length < 1 ||
    raw.keys.length > 16
  )
    throw new Error("Runner trust configuration schema is invalid.");

  const keys: TrustedPublicKey[] = raw.keys.map((value: unknown) => {
    if (
      !isRecord(value) ||
      Object.keys(value).some(
        (key) =>
          ![
            "keyId",
            "issuer",
            "publicKeyPem",
            "status",
            "notBefore",
            "notAfter",
            "revokedAt",
          ].includes(key),
      ) ||
      typeof value.keyId !== "string" ||
      !/^[A-Za-z0-9._-]{1,100}$/.test(value.keyId) ||
      typeof value.issuer !== "string" ||
      value.issuer.trim().length === 0 ||
      value.issuer.length > 200 ||
      typeof value.publicKeyPem !== "string" ||
      value.publicKeyPem.length > 4_096 ||
      !value.publicKeyPem.startsWith("-----BEGIN PUBLIC KEY-----") ||
      !["active", "retired", "revoked"].includes(String(value.status)) ||
      (value.notBefore !== undefined && typeof value.notBefore !== "string") ||
      (value.notAfter !== undefined && typeof value.notAfter !== "string") ||
      (value.revokedAt !== undefined && typeof value.revokedAt !== "string") ||
      (value.status === "retired" && value.notAfter === undefined) ||
      (value.status === "revoked" && value.revokedAt === undefined) ||
      (value.status !== "revoked" && value.revokedAt !== undefined)
    )
      throw new Error("Runner trusted issuer/key entry is invalid.");
    let publicKey;
    try {
      publicKey = createPublicKey(value.publicKeyPem);
    } catch {
      throw new Error("Runner trusted public key is invalid.");
    }
    if (
      publicKey.type !== "public" ||
      publicKey.asymmetricKeyType !== "ed25519"
    )
      throw new Error("Runner trusted key must be an Ed25519 public key.");
    return {
      keyId: value.keyId as string,
      issuer: value.issuer as string,
      publicKey,
      status: value.status as TrustedPublicKey["status"],
      ...(value.notBefore ? { notBefore: value.notBefore as string } : {}),
      ...(value.notAfter ? { notAfter: value.notAfter as string } : {}),
      ...(value.revokedAt ? { revokedAt: value.revokedAt as string } : {}),
    };
  });
  return new InMemoryTrustStore(keys);
}
