import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
  type KeyLike,
  KeyObject,
} from "node:crypto";

export type ScopePermission =
  | "read"
  | "mutations"
  | "syntheticIdentities"
  | "internalNetwork";

export interface AuthorizationScopePayload {
  version: 1;
  assessmentId: string;
  issuer: string;
  subject: string;
  targetOrigins: string[];
  environment: "local" | "preview" | "staging" | "production";
  permissions: ScopePermission[];
  limits: {
    maxRequests: number;
    maxCleanupRequests: number;
    rateLimitPerSecond: number;
    deadlineMs: number;
  };
  issuedAt: string;
  expiresAt: string;
  nonce: string;
}

export interface SignedAuthorizationScope {
  keyId: string;
  payload: AuthorizationScopePayload;
  signature: string;
}

const permissions = new Set<ScopePermission>([
  "read",
  "mutations",
  "syntheticIdentities",
  "internalNetwork",
]);
const environments = new Set(["local", "preview", "staging", "production"]);

function canonical(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean")
    return JSON.stringify(value);
  if (typeof value === "number" && Number.isFinite(value))
    return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (typeof value !== "object")
    throw new Error("Scope contains a non-JSON value.");
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null)
    throw new Error("Scope must contain plain JSON objects.");
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`).join(",")}}`;
}

function requireText(value: unknown, name: string, maxLength: number): string {
  if (
    typeof value !== "string" ||
    value.trim().length === 0 ||
    value.length > maxLength
  )
    throw new Error(`Signed scope ${name} is invalid.`);
  return value;
}

function scopePayload(value: unknown): AuthorizationScopePayload {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("Signed scope payload is invalid.");
  const input = value as Record<string, unknown>;
  const expected = [
    "version",
    "assessmentId",
    "issuer",
    "subject",
    "targetOrigins",
    "environment",
    "permissions",
    "limits",
    "issuedAt",
    "expiresAt",
    "nonce",
  ];
  if (Object.keys(input).some((key) => !expected.includes(key)))
    throw new Error("Signed scope contains an unknown payload field.");
  if (input.version !== 1)
    throw new Error("Signed scope version is unsupported.");
  requireText(input.assessmentId, "assessmentId", 200);
  requireText(input.issuer, "issuer", 200);
  requireText(input.subject, "subject", 200);
  requireText(input.nonce, "nonce", 200);
  if (
    !Array.isArray(input.targetOrigins) ||
    input.targetOrigins.length < 1 ||
    input.targetOrigins.length > 100 ||
    !input.targetOrigins.every((origin) => {
      if (typeof origin !== "string") return false;
      try {
        const parsed = new URL(origin);
        return (
          ["http:", "https:"].includes(parsed.protocol) &&
          parsed.origin === origin &&
          parsed.username === "" &&
          parsed.password === ""
        );
      } catch {
        return false;
      }
    }) ||
    new Set(input.targetOrigins).size !== input.targetOrigins.length
  )
    throw new Error("Signed scope targetOrigins must be unique exact origins.");
  if (
    typeof input.environment !== "string" ||
    !environments.has(input.environment)
  )
    throw new Error("Signed scope environment is invalid.");
  if (
    !Array.isArray(input.permissions) ||
    input.permissions.length < 1 ||
    !input.permissions.every(
      (permission) =>
        typeof permission === "string" &&
        permissions.has(permission as ScopePermission),
    ) ||
    new Set(input.permissions).size !== input.permissions.length ||
    !input.permissions.includes("read")
  )
    throw new Error("Signed scope permissions are invalid.");
  if (
    !input.limits ||
    typeof input.limits !== "object" ||
    Array.isArray(input.limits)
  )
    throw new Error("Signed scope limits are invalid.");
  const limits = input.limits as Record<string, unknown>;
  if (
    Object.keys(limits).some(
      (key) =>
        ![
          "maxRequests",
          "maxCleanupRequests",
          "rateLimitPerSecond",
          "deadlineMs",
        ].includes(key),
    ) ||
    !Number.isSafeInteger(limits.maxRequests) ||
    Number(limits.maxRequests) < 1 ||
    Number(limits.maxRequests) > 500 ||
    !Number.isSafeInteger(limits.maxCleanupRequests) ||
    Number(limits.maxCleanupRequests) < 1 ||
    Number(limits.maxCleanupRequests) > 200 ||
    !Number.isSafeInteger(limits.rateLimitPerSecond) ||
    Number(limits.rateLimitPerSecond) < 1 ||
    Number(limits.rateLimitPerSecond) > 20 ||
    !Number.isSafeInteger(limits.deadlineMs) ||
    Number(limits.deadlineMs) < 1_000 ||
    Number(limits.deadlineMs) > 30 * 60_000
  )
    throw new Error("Signed scope limits exceed the supported bounds.");
  const issuedAt = requireText(input.issuedAt, "issuedAt", 40);
  const expiresAt = requireText(input.expiresAt, "expiresAt", 40);
  if (
    !Number.isFinite(Date.parse(issuedAt)) ||
    !Number.isFinite(Date.parse(expiresAt)) ||
    new Date(issuedAt).toISOString() !== issuedAt ||
    new Date(expiresAt).toISOString() !== expiresAt
  )
    throw new Error("Signed scope timestamps are invalid.");
  if (Date.parse(expiresAt) <= Date.parse(issuedAt))
    throw new Error("Signed scope expiry must follow issue time.");
  if (Date.parse(expiresAt) - Date.parse(issuedAt) > 24 * 60 * 60_000)
    throw new Error("Signed scope validity cannot exceed 24 hours.");
  return input as unknown as AuthorizationScopePayload;
}

export function createSignedAuthorizationScope(
  payload: AuthorizationScopePayload,
  keyId: string,
  privateKey: KeyLike | string | Buffer,
): SignedAuthorizationScope {
  if (!/^[A-Za-z0-9._-]{1,100}$/.test(keyId))
    throw new Error("Signed scope keyId is invalid.");
  const checked = scopePayload(payload);
  const key =
    privateKey instanceof KeyObject ? privateKey : createPrivateKey(privateKey);
  if (key.asymmetricKeyType !== "ed25519")
    throw new Error("Authorization scope signing key must be Ed25519.");
  const signature = sign(null, Buffer.from(canonical(checked)), key).toString(
    "base64url",
  );
  return { keyId, payload: checked, signature };
}

export function verifyAuthorizationScope(
  scope: SignedAuthorizationScope,
  trustedKeys: Record<string, KeyLike | string | Buffer>,
  input: {
    target: string;
    environment: AuthorizationScopePayload["environment"];
    reference: string;
    now?: number;
  },
): AuthorizationScopePayload {
  if (!scope || typeof scope !== "object" || Array.isArray(scope))
    throw new Error("A signed authorization scope is required.");
  if (!/^[A-Za-z0-9._-]{1,100}$/.test(scope.keyId))
    throw new Error("Signed scope keyId is invalid.");
  if (
    typeof scope.signature !== "string" ||
    !/^[A-Za-z0-9_-]{86}$/.test(scope.signature)
  )
    throw new Error("Signed scope signature encoding is invalid.");
  if (
    !trustedKeys ||
    typeof trustedKeys !== "object" ||
    (Object.getPrototypeOf(trustedKeys) !== Object.prototype &&
      Object.getPrototypeOf(trustedKeys) !== null)
  )
    throw new Error("Trusted scope key set is invalid.");
  if (!Object.hasOwn(trustedKeys, scope.keyId))
    throw new Error("Signed scope keyId is not trusted.");
  const keyInput = trustedKeys[scope.keyId];
  if (!keyInput) throw new Error("Signed scope keyId is not trusted.");
  const key =
    keyInput instanceof KeyObject ? keyInput : createPublicKey(keyInput);
  if (key.asymmetricKeyType !== "ed25519")
    throw new Error("Authorization scope verification key must be Ed25519.");
  const payload = scopePayload(scope.payload);
  const valid = verify(
    null,
    Buffer.from(canonical(payload)),
    key,
    Buffer.from(scope.signature, "base64url"),
  );
  if (
    Buffer.from(scope.signature, "base64url").toString("base64url") !==
      scope.signature ||
    !valid
  )
    throw new Error("Signed authorization scope signature is invalid.");
  const now = input.now ?? Date.now();
  const issuedAt = Date.parse(payload.issuedAt);
  const expiresAt = Date.parse(payload.expiresAt);
  if (issuedAt > now + 60_000)
    throw new Error("Signed authorization scope is not yet valid.");
  if (expiresAt <= now)
    throw new Error("Signed authorization scope has expired.");
  if (payload.environment !== input.environment)
    throw new Error("Signed authorization scope environment does not match.");
  if (payload.assessmentId !== input.reference)
    throw new Error("Signed authorization scope assessment does not match.");
  if (!payload.targetOrigins.includes(input.target))
    throw new Error("Attack target is outside the signed authorization scope.");
  return payload;
}

export function authorizationScopeDigest(
  scope: SignedAuthorizationScope,
): string {
  return createHash("sha256")
    .update(
      canonical({
        keyId: scope.keyId,
        payload: scopePayload(scope.payload),
        signature: scope.signature,
      }),
    )
    .digest("hex");
}
