import { randomUUID } from "node:crypto";
import type { CreateRunInput } from "./types.js";

export interface AuthorizationScopePayload {
  version: 1;
  assessmentId: string;
  issuer: string;
  subject: string;
  targetOrigins: string[];
  environment: CreateRunInput["environment"];
  permissions: NonNullable<CreateRunInput["permissions"]>;
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

export interface ScopeSigner {
  readonly publicKeyPem: string;
  sign(payload: AuthorizationScopePayload): Promise<SignedAuthorizationScope>;
}

export class RemoteScopeSigner implements ScopeSigner {
  constructor(
    private readonly endpoint: string,
    private readonly token: string,
    readonly publicKeyPem: string,
  ) {
    if (!endpoint.startsWith("https://"))
      throw new Error("Scope signing endpoint must use HTTPS.");
    if (token.length < 32) throw new Error("Scope signing token is too short.");
    if (!publicKeyPem.includes("PUBLIC KEY"))
      throw new Error("Scope signing public key is invalid.");
  }

  async sign(payload: AuthorizationScopePayload): Promise<SignedAuthorizationScope> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5_000);
    try {
      const response = await fetch(this.endpoint, {
        method: "POST",
        redirect: "error",
        headers: {
          authorization: `Bearer ${this.token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ purpose: "reaper-authorization-scope-v1", payload }),
        signal: controller.signal,
      });
      if (!response.ok)
        throw new Error(`Scope signer returned HTTP ${response.status}.`);
      const value = (await response.json()) as Partial<SignedAuthorizationScope>;
      if (
        typeof value.keyId !== "string" ||
        !/^[A-Za-z0-9._-]{1,100}$/.test(value.keyId) ||
        typeof value.signature !== "string" ||
        !/^[A-Za-z0-9_-]{86}$/.test(value.signature) ||
        JSON.stringify(value.payload) !== JSON.stringify(payload)
      )
        throw new Error("Scope signer returned an invalid envelope.");
      return value as SignedAuthorizationScope;
    } finally {
      clearTimeout(timeout);
    }
  }
}

export function buildScopePayload(input: {
  runId: string;
  assessmentId: string;
  workspaceId: string;
  target: string;
  environment: CreateRunInput["environment"];
  permissions: NonNullable<CreateRunInput["permissions"]>;
  limits: Required<NonNullable<CreateRunInput["limits"]>>;
}): AuthorizationScopePayload {
  const issuedAt = new Date();
  const expiresAt = new Date(
    issuedAt.getTime() + Math.min(input.limits.deadlineMs + 60_000, 24 * 60 * 60_000),
  );
  return {
    version: 1,
    assessmentId: input.assessmentId,
    issuer: "reaper-platform",
    subject: `workspace:${input.workspaceId}:run:${input.runId}`,
    targetOrigins: [input.target],
    environment: input.environment,
    permissions: input.permissions,
    limits: input.limits,
    issuedAt: issuedAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
    nonce: randomUUID(),
  };
}
