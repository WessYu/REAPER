import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import http from "node:http";
import { once } from "node:events";
import {
  createSignedAuthorizationScope,
  runAttack,
  verifyAuthorizationScope,
} from "../dist/index.js";

function scopePayload(target = "https://app.example.test") {
  const now = Date.now();
  return {
    version: 1,
    assessmentId: "assessment-42",
    issuer: "reaper-test-authority",
    subject: "security-team",
    targetOrigins: [target],
    environment: "staging",
    permissions: ["read"],
    limits: {
      maxRequests: 3,
      maxCleanupRequests: 2,
      rateLimitPerSecond: 2,
      deadlineMs: 10_000,
    },
    issuedAt: new Date(now - 1_000).toISOString(),
    expiresAt: new Date(now + 60_000).toISOString(),
    nonce: "one-time-assessment-42",
  };
}

test("Ed25519 scope signature is canonical and verifies exact assessment context", () => {
  const keys = generateKeyPairSync("ed25519");
  const payload = scopePayload();
  const signed = createSignedAuthorizationScope(
    payload,
    "test-2026",
    keys.privateKey,
  );
  assert.deepEqual(
    verifyAuthorizationScope(
      signed,
      { "test-2026": keys.publicKey },
      {
        target: "https://app.example.test",
        environment: "staging",
        reference: "assessment-42",
      },
    ),
    payload,
  );

  const reordered = {
    ...signed,
    payload: Object.fromEntries(Object.entries(signed.payload).reverse()),
  };
  assert.doesNotThrow(() =>
    verifyAuthorizationScope(
      reordered,
      { "test-2026": keys.publicKey },
      {
        target: "https://app.example.test",
        environment: "staging",
        reference: "assessment-42",
      },
    ),
  );
});

test("signed scope rejects tampering, expired scope, untrusted keys and context escape", () => {
  const keys = generateKeyPairSync("ed25519");
  const signed = createSignedAuthorizationScope(
    scopePayload(),
    "test-2026",
    keys.privateKey,
  );
  const context = {
    target: "https://app.example.test",
    environment: "staging",
    reference: "assessment-42",
  };
  const verify = (
    scope,
    trusted = { "test-2026": keys.publicKey },
    current = context,
  ) => verifyAuthorizationScope(scope, trusted, current);

  assert.throws(
    () =>
      verify({
        ...signed,
        payload: { ...signed.payload, subject: "attacker" },
      }),
    /signature is invalid/,
  );
  assert.throws(() => verify(signed, {}), /not trusted/);
  assert.throws(
    () =>
      verify(signed, undefined, {
        ...context,
        target: "https://other.example.test",
      }),
    /outside/,
  );
  assert.throws(
    () => verify(signed, undefined, { ...context, environment: "production" }),
    /environment/,
  );
  assert.throws(
    () =>
      verify(signed, undefined, { ...context, reference: "other-assessment" }),
    /assessment/,
  );
  assert.throws(
    () =>
      verifyAuthorizationScope(
        signed,
        { "test-2026": keys.publicKey },
        { ...context, now: Date.parse(signed.payload.expiresAt) },
      ),
    /expired/,
  );
});

test("scope payload rejects ambiguous origins, excessive bounds and unknown permissions", () => {
  const keys = generateKeyPairSync("ed25519");
  for (const mutate of [
    (payload) => (payload.targetOrigins = ["https://app.example.test/path"]),
    (payload) => (payload.limits.maxRequests = 501),
    (payload) => (payload.permissions = ["read", "execute"]),
  ]) {
    const payload = scopePayload();
    mutate(payload);
    assert.throws(() =>
      createSignedAuthorizationScope(payload, "test-2026", keys.privateKey),
    );
  }
});

test("strict attack mode enforces signed target, mutation permission and budgets", async () => {
  let requests = 0;
  const server = http.createServer((_req, res) => {
    requests++;
    res.statusCode = 200;
    res.end("ok");
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const target = `http://127.0.0.1:${address.port}`;
  const keys = generateKeyPairSync("ed25519");
  const signed = createSignedAuthorizationScope(
    {
      ...scopePayload(target),
      assessmentId: "strict-assessment",
      limits: {
        maxRequests: 1,
        maxCleanupRequests: 1,
        rateLimitPerSecond: 20,
        deadlineMs: 10_000,
      },
    },
    "strict-key",
    keys.privateKey,
  );
  const attackConfig = {
    attack: {
      allowedTargets: [target],
      requireSignedScope: true,
      authorization: {
        acknowledged: true,
        reference: "strict-assessment",
        environment: "staging",
      },
      maxRequests: 50,
      rateLimitPerSecond: 20,
      scenarios: [
        {
          id: "bounded-scope",
          title: "Respect signed request cap",
          dimension: "session",
          steps: [
            { name: "first", path: "/one" },
            { name: "second", path: "/two" },
          ],
        },
      ],
    },
  };
  try {
    const result = await runAttack(target, attackConfig, {
      scopeManifest: signed,
      trustedScopeKeys: { "strict-key": keys.publicKey },
    });
    assert.equal(requests, 1);
    assert.equal(result.attack.requests, 1);
    assert.equal(result.attack.signedScope.assessmentId, "strict-assessment");
    assert.match(result.attack.signedScope.digest, /^[a-f0-9]{64}$/);
    assert.match(
      result.diagnostics[0]?.message ?? "",
      /request budget exceeded \(1\)/,
    );

    const outside = {
      ...signed,
      payload: {
        ...signed.payload,
        targetOrigins: ["https://other.example.test"],
      },
    };
    await assert.rejects(
      runAttack(target, attackConfig, {
        scopeManifest: outside,
        trustedScopeKeys: { "strict-key": keys.publicKey },
      }),
      /signature is invalid/,
    );

    await assert.rejects(
      runAttack(
        target,
        {
          attack: {
            ...attackConfig.attack,
            allowMutations: true,
            scenarios: [
              {
                id: "mutation-scope",
                title: "Reject unsigned mutation permission",
                dimension: "session",
                steps: [{ name: "write", path: "/write", method: "POST" }],
                cleanup: [
                  { name: "cleanup", path: "/write", method: "DELETE" },
                ],
              },
            ],
          },
        },
        {
          scopeManifest: signed,
          trustedScopeKeys: { "strict-key": keys.publicKey },
        },
      ),
      /does not permit mutations/,
    );
    assert.equal(requests, 1);
  } finally {
    server.closeAllConnections?.();
    server.close();
    await once(server, "close");
  }
});

test("strict attack mode stops new requests when the signed scope expires mid-run", async () => {
  let requests = 0;
  const server = http.createServer((_req, res) => {
    requests++;
    res.statusCode = 200;
    res.end("ok");
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const target = `http://127.0.0.1:${address.port}`;
  const keys = generateKeyPairSync("ed25519");
  const now = Date.now();
  const signed = createSignedAuthorizationScope(
    {
      ...scopePayload(target),
      assessmentId: "short-scope",
      issuedAt: new Date(now - 1_000).toISOString(),
      expiresAt: new Date(now + 500).toISOString(),
      limits: {
        maxRequests: 5,
        maxCleanupRequests: 1,
        rateLimitPerSecond: 1,
        deadlineMs: 10_000,
      },
    },
    "expiry-key",
    keys.privateKey,
  );
  try {
    const result = await runAttack(
      target,
      {
        attack: {
          allowedTargets: [target],
          requireSignedScope: true,
          authorization: {
            acknowledged: true,
            reference: "short-scope",
            environment: "staging",
          },
          scenarios: [
            {
              id: "expire-between-requests",
              title: "Do not start requests after scope expiry",
              dimension: "session",
              steps: [
                { name: "first", path: "/one" },
                { name: "after expiry", path: "/two" },
              ],
            },
          ],
        },
      },
      {
        scopeManifest: signed,
        trustedScopeKeys: { "expiry-key": keys.publicKey },
      },
    );
    assert.equal(requests, 1);
    assert.ok(
      result.diagnostics.some((item) =>
        /scope expired during the run/.test(item.message),
      ),
    );
  } finally {
    server.closeAllConnections?.();
    server.close();
    await once(server, "close");
  }
});
