import { isIP } from "node:net";

function exactPublicOrigin(value: unknown): string {
  if (typeof value !== "string" || value.length > 2048 || value.trim() !== value)
    throw new Error("Commercial target origin is invalid.");
  const parsed = new URL(value);
  if (
    parsed.protocol !== "https:" ||
    parsed.origin !== value ||
    parsed.port ||
    parsed.username ||
    parsed.password ||
    isIP(parsed.hostname) !== 0 ||
    !parsed.hostname.includes(".") ||
    !/^[a-z0-9.-]+$/.test(parsed.hostname)
  )
    throw new Error("Commercial target must be an exact public HTTPS hostname origin.");
  return value;
}

export function requireOperatorAuthorizedOrigin(
  target: string,
  configured: string | undefined,
): void {
  if (!configured || configured.length > 8192)
    throw new Error("Commercial target authorization allowlist is unavailable.");
  let decoded: unknown;
  try {
    decoded = JSON.parse(configured);
  } catch {
    throw new Error("Commercial target authorization allowlist is malformed.");
  }
  if (!Array.isArray(decoded) || decoded.length < 1 || decoded.length > 20)
    throw new Error("Commercial target authorization allowlist is invalid.");
  const origins = decoded.map(exactPublicOrigin);
  if (new Set(origins).size !== origins.length)
    throw new Error("Commercial target authorization allowlist has duplicate origins.");
  if (!origins.includes(exactPublicOrigin(target)))
    throw new Error("Target is not on the operator-reviewed commercial authorization allowlist.");
}
