import test from "node:test";
import assert from "node:assert/strict";
import {
  apiKeyLookup,
  createApiKeyMaterial,
  parseBearerHeader,
  requireRole,
} from "../dist/auth.js";

const pepper = "p".repeat(64);

test("API keys expose the secret once and derive a stable lookup digest", () => {
  const issued = createApiKeyMaterial(pepper);
  assert.match(issued.token, /^reaper_live_[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}$/);
  const lookup = apiKeyLookup(issued.token, pepper);
  assert.equal(lookup.id, issued.id);
  assert.equal(lookup.secretHash, issued.secretHash);
  assert.notEqual(issued.secretHash, issued.token);
});

test("Bearer parser and role hierarchy fail closed", () => {
  assert.equal(parseBearerHeader("Bearer abc"), "abc");
  assert.throws(() => parseBearerHeader("Basic abc"), /Bearer/);
  const viewer = {
    principalId: "viewer",
    workspaceId: "00000000-0000-4000-8000-000000000001",
    role: "viewer",
    apiKeyId: "00000000-0000-4000-8000-000000000002",
  };
  assert.throws(() => requireRole(viewer, "analyst"), /analyst/);
  assert.doesNotThrow(() =>
    requireRole({ ...viewer, role: "admin" }, "analyst"),
  );
});
