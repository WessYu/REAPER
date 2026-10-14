const DAY_MS = 24 * 60 * 60 * 1000;
export const DEFAULT_API_KEY_DAYS = 30;
export const MAX_API_KEY_DAYS = 90;

export function resolveApiKeyExpiry(
  requested: string | null | undefined,
  now = Date.now(),
): string {
  if (!Number.isFinite(now)) throw new Error("Current time is invalid.");
  const parsed =
    requested === null || requested === undefined
      ? now + DEFAULT_API_KEY_DAYS * DAY_MS
      : Date.parse(requested);
  if (
    !Number.isFinite(parsed) ||
    parsed <= now ||
    parsed > now + MAX_API_KEY_DAYS * DAY_MS
  )
    throw new Error("expiresAt must be a future timestamp within 90 days.");
  return new Date(parsed).toISOString();
}
