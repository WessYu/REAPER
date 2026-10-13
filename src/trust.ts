import type { KeyLike } from "node:crypto";

export type TrustedKeyStatus = "active" | "retired" | "revoked";

export interface TrustedPublicKey {
  keyId: string;
  publicKey: KeyLike | string | Buffer;
  status: TrustedKeyStatus;
  notBefore?: string;
  notAfter?: string;
  revokedAt?: string;
}

export interface TrustStore {
  get(keyId: string): TrustedPublicKey | undefined;
}

export type TrustedKeySource =
  | Record<string, KeyLike | string | Buffer>
  | TrustStore;

const KEY_ID = /^[A-Za-z0-9._-]{1,100}$/;

function timestamp(value: string | undefined, name: string): number | undefined {
  if (value === undefined) return undefined;
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value)
    throw new Error(`Trusted key ${name} is invalid.`);
  return parsed;
}

function validate(entry: TrustedPublicKey): TrustedPublicKey {
  if (!entry || typeof entry !== "object" || Array.isArray(entry))
    throw new Error("Trusted key entry is invalid.");
  if (!KEY_ID.test(entry.keyId)) throw new Error("Trusted key id is invalid.");
  if (!["active", "retired", "revoked"].includes(entry.status))
    throw new Error("Trusted key status is invalid.");
  const notBefore = timestamp(entry.notBefore, "notBefore");
  const notAfter = timestamp(entry.notAfter, "notAfter");
  const revokedAt = timestamp(entry.revokedAt, "revokedAt");
  if (
    notBefore !== undefined &&
    notAfter !== undefined &&
    notAfter <= notBefore
  )
    throw new Error("Trusted key validity window is invalid.");
  if (entry.status === "revoked" && revokedAt === undefined)
    throw new Error("Revoked trusted keys require revokedAt.");
  return entry;
}

export class InMemoryTrustStore implements TrustStore {
  readonly #keys: Map<string, TrustedPublicKey>;

  constructor(keys: TrustedPublicKey[]) {
    this.#keys = new Map();
    for (const raw of keys) {
      const key = validate(raw);
      if (this.#keys.has(key.keyId))
        throw new Error("Trusted key ids must be unique.");
      this.#keys.set(key.keyId, key);
    }
  }

  get(keyId: string): TrustedPublicKey | undefined {
    const value = this.#keys.get(keyId);
    return value ? { ...value } : undefined;
  }
}

function isTrustStore(value: TrustedKeySource): value is TrustStore {
  return (
    !!value &&
    typeof value === "object" &&
    typeof (value as TrustStore).get === "function"
  );
}

export function resolveTrustedPublicKey(
  source: TrustedKeySource,
  keyId: string,
  now = Date.now(),
): KeyLike | string | Buffer {
  if (!KEY_ID.test(keyId)) throw new Error("Trusted key id is invalid.");
  if (!source || typeof source !== "object")
    throw new Error("Trusted key source is invalid.");

  if (!isTrustStore(source)) {
    if (
      (Object.getPrototypeOf(source) !== Object.prototype &&
        Object.getPrototypeOf(source) !== null) ||
      !Object.hasOwn(source, keyId)
    )
      throw new Error("Signed artifact keyId is not trusted.");
    const descriptor = Object.getOwnPropertyDescriptor(source, keyId);
    if (!descriptor || !Object.hasOwn(descriptor, "value"))
      throw new Error("Trusted key entries must be data properties.");
    const key = descriptor.value as KeyLike | string | Buffer | undefined;
    if (!key) throw new Error("Signed artifact keyId is not trusted.");
    return key;
  }

  const entry = source.get(keyId);
  if (!entry) throw new Error("Signed artifact keyId is not trusted.");
  const key = validate(entry);
  if (key.status === "revoked")
    throw new Error("Signed artifact verification key is revoked.");
  const notBefore = timestamp(key.notBefore, "notBefore");
  const notAfter = timestamp(key.notAfter, "notAfter");
  if (notBefore !== undefined && now < notBefore)
    throw new Error("Signed artifact verification key is not yet valid.");
  if (notAfter !== undefined && now >= notAfter)
    throw new Error("Signed artifact verification key has expired.");
  return key.publicKey;
}
