import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import {
  InMemoryTrustStore,
  createSignedAuthorizationScope,
  createSignedRulePack,
  verifyAuthorizationScope,
  verifySignedRulePack,
} from "../dist/index.js";

function payload() {
  const now = Date.now();
  return {
    version: 1,
    assessmentId: "trust-test",
    issuer: "issuer",
    subject: "subject",
    targetOrigins: ["https://preview.example.test"],
    environment: "staging",
    permissions: ["read"],
    limits: {
      maxRequests: 1,
      maxCleanupRequests: 1,
      rateLimitPerSecond: 1,
      deadlineMs: 1000,
    },
    issuedAt: new Date(now - 1000).toISOString(),
    expiresAt: new Date(now + 60_000).toISOString(),
    nonce: "trust-test-nonce",
  };
}

test("trust store accepts active and overlapping rotation keys", () => {
  const k1 = generateKeyPairSync("ed25519");
  const k2 = generateKeyPairSync("ed25519");
  const signed = createSignedAuthorizationScope(payload(), "k1", k1.privateKey);
  const now = Date.now();
  const store = new InMemoryTrustStore([
    {
      keyId: "k1",
      publicKey: k1.publicKey,
      status: "retired",
      notBefore: new Date(now - 60_000).toISOString(),
      notAfter: new Date(now + 60_000).toISOString(),
    },
    {
      keyId: "k2",
      publicKey: k2.publicKey,
      status: "active",
      notBefore: new Date(now - 1000).toISOString(),
      notAfter: new Date(now + 120_000).toISOString(),
    },
  ]);
  assert.doesNotThrow(() =>
    verifyAuthorizationScope(signed, store, {
      target: "https://preview.example.test",
      environment: "staging",
      reference: "trust-test",
      now,
    }),
  );
});

test("trust store rejects revoked not-yet-valid and expired keys", () => {
  const keys = generateKeyPairSync("ed25519");
  const signed = createSignedAuthorizationScope(
    payload(),
    "scope-key",
    keys.privateKey,
  );
  const now = Date.now();
  for (const entry of [
    {
      keyId: "scope-key",
      publicKey: keys.publicKey,
      status: "revoked",
      revokedAt: new Date(now - 1000).toISOString(),
    },
    {
      keyId: "scope-key",
      publicKey: keys.publicKey,
      status: "active",
      notBefore: new Date(now + 60_000).toISOString(),
    },
    {
      keyId: "scope-key",
      publicKey: keys.publicKey,
      status: "retired",
      notAfter: new Date(now - 1).toISOString(),
    },
  ]) {
    const store = new InMemoryTrustStore([entry]);
    assert.throws(
      () =>
        verifyAuthorizationScope(signed, store, {
          target: "https://preview.example.test",
          environment: "staging",
          reference: "trust-test",
          now,
        }),
      /revoked|not yet valid|expired/,
    );
  }
});


test("rule-pack verification uses the same revocation lifecycle boundary", () => {
  const keys = generateKeyPairSync("ed25519");
  const pack = createSignedRulePack(
    {
      formatVersion: 1,
      packId: "trust-pack",
      version: "1.0.0",
      compatibility: { engineVersions: ["0.2.0"] },
      rules: [
        {
          id: "literal-check",
          title: "Literal check",
          description: "Detect a bounded literal marker for trust testing.",
          severity: "LOW",
          category: "SQL Safety",
          contains: "trustMarker",
          recommendation: "Review the bounded test marker before release.",
        },
      ],
    },
    "rule-key",
    keys.privateKey,
  );
  const store = new InMemoryTrustStore([
    {
      keyId: "rule-key",
      publicKey: keys.publicKey,
      status: "revoked",
      revokedAt: new Date().toISOString(),
    },
  ]);
  assert.throws(
    () => verifySignedRulePack(pack, store),
    /revoked/,
  );
});
