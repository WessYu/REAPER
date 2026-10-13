import {
  createHmac,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import type { Pool } from "pg";
import type { IssuedApiKey, PlatformRole, RequestContext } from "./types.js";

const KEY_PREFIX = "reaper_live_";
const ROLE_WEIGHT: Record<PlatformRole, number> = {
  viewer: 10,
  analyst: 20,
  admin: 30,
};

function hmacHex(value: string, pepper: string): string {
  if (pepper.length < 32)
    throw new Error(
      "REAPER_PLATFORM_API_KEY_PEPPER must be at least 32 characters.",
    );
  return createHmac("sha256", pepper).update(value).digest("hex");
}

function safeTextEqual(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

export function parseBearerHeader(header: string | undefined): string {
  if (!header) throw new Error("Missing Authorization header.");
  const match = /^Bearer ([^\s]+)$/.exec(header);
  if (!match?.[1]) throw new Error("Authorization must use a Bearer token.");
  return match[1];
}

export function createApiKeyMaterial(
  pepper: string,
  expiresAt: string | null = null,
): IssuedApiKey & { secretHash: string } {
  const id = randomUUID();
  const secret = randomBytes(32).toString("base64url");
  const token = `${KEY_PREFIX}${id}.${secret}`;
  return {
    id,
    token,
    expiresAt,
    secretHash: hmacHex(token, pepper),
  };
}

export function apiKeyLookup(
  token: string,
  pepper: string,
): { id: string; secretHash: string } {
  const match = /^reaper_live_([0-9a-f-]{36})\.([A-Za-z0-9_-]{43})$/.exec(
    token,
  );
  if (!match?.[1]) throw new Error("API key format is invalid.");
  return { id: match[1], secretHash: hmacHex(token, pepper) };
}

export async function authenticateApiKey(
  pool: Pool,
  token: string,
  pepper: string,
): Promise<RequestContext> {
  const lookup = apiKeyLookup(token, pepper);
  const result = await pool.query<{
    api_key_id: string;
    workspace_id: string;
    principal_id: string;
    role: PlatformRole;
  }>("SELECT * FROM reaper_control.authenticate_api_key($1::uuid, $2::text)", [
    lookup.id,
    lookup.secretHash,
  ]);
  const row = result.rows[0];
  if (!row) throw new Error("API key is invalid, expired or revoked.");
  return {
    apiKeyId: row.api_key_id,
    workspaceId: row.workspace_id,
    principalId: row.principal_id,
    role: row.role,
  };
}

export function requireRole(
  context: RequestContext,
  minimum: PlatformRole,
): void {
  if (ROLE_WEIGHT[context.role] < ROLE_WEIGHT[minimum])
    throw new Error(`Role ${minimum} or higher is required.`);
}

export function verifyBootstrapToken(
  supplied: string | undefined,
  expected: string,
): void {
  if (!expected || expected.length < 32)
    throw new Error(
      "REAPER_PLATFORM_BOOTSTRAP_TOKEN must be configured with at least 32 characters.",
    );
  if (!supplied || !safeTextEqual(supplied, expected))
    throw new Error("Bootstrap authorization failed.");
}
