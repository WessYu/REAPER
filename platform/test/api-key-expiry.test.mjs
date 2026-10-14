import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  resolveApiKeyExpiry,
  DEFAULT_API_KEY_DAYS,
  MAX_API_KEY_DAYS,
} from "../dist/api-key-expiry.js";

const now = Date.parse("2026-10-14T12:00:00.000Z");
const day = 24 * 60 * 60 * 1000;

test("new API keys expire by default rather than persisting indefinitely", () => {
  const expiry = resolveApiKeyExpiry(undefined, now);
  assert.equal(Date.parse(expiry) - now, DEFAULT_API_KEY_DAYS * day);
  assert.equal(resolveApiKeyExpiry(null, now), expiry);
});

test("API key expiration validates explicit bounded dates", () => {
  assert.equal(
    Date.parse(resolveApiKeyExpiry(new Date(now + 10 * day).toISOString(), now)),
    now + 10 * day,
  );
  assert.throws(
    () => resolveApiKeyExpiry(new Date(now - day).toISOString(), now),
    /within 90 days/,
  );
  assert.throws(
    () =>
      resolveApiKeyExpiry(
        new Date(now + (MAX_API_KEY_DAYS + 1) * day).toISOString(),
        now,
      ),
    /within 90 days/,
  );
  assert.throws(() => resolveApiKeyExpiry("invalid", now), /within 90 days/);
});

test("hosted staging API keys have finite expiration and no unlimited fallback", async () => {
  const file = new URL(
    "../../supabase/functions/reaper-platform/index.ts",
    import.meta.url,
  );
  const content = await readFile(file, "utf8");
  assert.match(content, /now \+ 30 \* 24 \* 60 \* 60 \* 1000/);
  assert.match(content, /expiry > now \+ 90 \* 24 \* 60 \* 60 \* 1000/);
  assert.doesNotMatch(content, /body\.expiresAt === null\s*\? null/);
});
