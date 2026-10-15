import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import http from "node:http";
import { once } from "node:events";
import {
  createAttackJob,
  createSignedAuthorizationScope,
  ENGINE_VERSION,
  InMemoryTrustStore,
  runAttackJob,
  verifyAuthorizationScope,
} from "../dist/index.js";
import { parseRunnerTrustConfig } from "../dist/runner-trust.js";

function trustConfig(entries) {
  return JSON.stringify({ version: 1, keys: entries });
}

function entry(keyId, issuer, publicKey, status = "active", extra = {}) {
  return {
    keyId,
    issuer,
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }),
    status,
    ...extra,
  };
}

function scope(target, privateKey, keyId = "key-a", issuer = "reaper-platform") {
  const now = Date.now();
  return createSignedAuthorizationScope(
    {
      version: 1,
      assessmentId: "independent-trust-assessment",
      issuer,
      subject: "authorized-user",
      targetOrigins: [target],
      environment: "staging",
      permissions: ["read"],
      limits: {
        maxRequests: 10,
        maxCleanupRequests: 1,
        rateLimitPerSecond: 5,
        deadlineMs: 5_000,
      },
      issuedAt: new Date(now - 1_000).toISOString(),
      expiresAt: new Date(now + 60_000).toISOString(),
      nonce: "independent-trust-nonce",
    },
    keyId,
    privateKey,
  );
}

function job(target, signed) {
  const authorization = {
    acknowledged: true,
    reference: "independent-trust-assessment",
    environment: "staging",
    expiresAt: signed.payload.expiresAt,
  };
  return createAttackJob({
    target,
    authorization,
    config: {
      attack: {
        allowedTargets: [target],
        authorization,
        requireSignedScope: true,
        scenarios: [
          {
            id: "trust-read",
            title: "Authorized read",
            dimension: "session",
            steps: [
              {
                name: "read",
                path: "/",
                expect: { allowedStatuses: [200] },
              },
            ],
          },
        ],
      },
    },
    limits: {
      deadlineMs: 5_000,
      cleanupGraceMs: 1_000,
      memoryMb: 128,
      maxOutputBytes: 1_000_000,
    },
    engineVersion: ENGINE_VERSION,
    scopeManifest: signed,
  });
}

test("runner trust config enforces independent issuer binding and key type", () => {
  const a = generateKeyPairSync("ed25519");
  const b = generateKeyPairSync("ed25519");
  const target = "https://preview.example.test";
  const signed = scope(target, a.privateKey);
  const store = parseRunnerTrustConfig(
    trustConfig([entry("key-a", "reaper-platform", a.publicKey)]),
  );
  assert.doesNotThrow(() =>
    verifyAuthorizationScope(signed, store, {
      target,
      environment: "staging",
      reference: "independent-trust-assessment",
    }),
  );
  const foreignIssuer = parseRunnerTrustConfig(
    trustConfig([entry("key-a", "attacker", a.publicKey)]),
  );
  assert.throws(
    () =>
      verifyAuthorizationScope(signed, foreignIssuer, {
        target,
        environment: "staging",
        reference: "independent-trust-assessment",
      }),
    /issuer does not match trusted key/,
  );
  const wrongKey = parseRunnerTrustConfig(
    trustConfig([entry("key-a", "reaper-platform", b.publicKey)]),
  );
  assert.throws(
    () =>
      verifyAuthorizationScope(signed, wrongKey, {
        target,
        environment: "staging",
        reference: "independent-trust-assessment",
      }),
    /signature is invalid/,
  );
});

test("runner trust parser rejects unknown fields, private keys and missing rotation expiry", () => {
  const a = generateKeyPairSync("ed25519");
  const key = entry("key-a", "reaper-platform", a.publicKey);
  assert.throws(() => parseRunnerTrustConfig("{}"), /schema is invalid/);
  assert.throws(
    () => parseRunnerTrustConfig(trustConfig([{ ...key, extra: "untrusted" }])),
    /entry is invalid/,
  );
  assert.throws(
    () => parseRunnerTrustConfig(trustConfig([{ ...key, status: "retired" }])),
    /entry is invalid/,
  );
  assert.throws(
    () =>
      parseRunnerTrustConfig(
        trustConfig([
          {
            ...key,
            publicKeyPem: a.privateKey.export({
              type: "pkcs8",
              format: "pem",
            }),
          },
        ]),
      ),
    /entry is invalid/,
  );
});

test("rotation accepts bounded overlap but rejects revoked and expired issuers", () => {
  const a = generateKeyPairSync("ed25519");
  const b = generateKeyPairSync("ed25519");
  const target = "https://preview.example.test";
  const signed = scope(target, a.privateKey);
  const now = Date.now();
  const retired = entry("key-a", "reaper-platform", a.publicKey, "retired", {
    notAfter: new Date(now + 30_000).toISOString(),
  });
  const current = entry("key-b", "reaper-platform", b.publicKey);
  const input = {
    target,
    environment: "staging",
    reference: "independent-trust-assessment",
    now,
  };
  assert.doesNotThrow(() =>
    verifyAuthorizationScope(
      signed,
      parseRunnerTrustConfig(trustConfig([retired, current])),
      input,
    ),
  );
  assert.throws(
    () =>
      verifyAuthorizationScope(
        signed,
        parseRunnerTrustConfig(
          trustConfig([
            { ...retired, notAfter: new Date(now - 1000).toISOString() },
            current,
          ]),
        ),
        input,
      ),
    /expired/,
  );
  assert.throws(
    () =>
      verifyAuthorizationScope(
        signed,
        parseRunnerTrustConfig(
          trustConfig([
            {
              ...retired,
              status: "revoked",
              revokedAt: new Date(now - 1000).toISOString(),
              notAfter: undefined,
            },
            current,
          ]),
        ),
        input,
      ),
    /revoked/,
  );
});

test("signed envelope with embedded public key B is rejected even when A is trusted", () => {
  const a = generateKeyPairSync("ed25519");
  const b = generateKeyPairSync("ed25519");
  const target = "https://preview.example.test";
  const signed = scope(target, a.privateKey);
  const store = new InMemoryTrustStore([
    { keyId: "key-a", issuer: "reaper-platform", publicKey: a.publicKey, status: "active" },
  ]);
  assert.throws(
    () =>
      verifyAuthorizationScope(
        { ...signed, publicKey: b.publicKey.export({ type: "spki", format: "pem" }) },
        store,
        {
          target,
          environment: "staging",
          reference: "independent-trust-assessment",
        },
      ),
    /unknown fields/,
  );
});

test("runner rejects embedded verifier keys and missing independent trust before any request", async () => {
  const a = generateKeyPairSync("ed25519");
  const b = generateKeyPairSync("ed25519");
  const target = "http://127.0.0.1:45001";
  const signed = scope(target, a.privateKey);
  const current = job(target, signed);
  current.trustedScopeKeys = {
    "key-a": b.publicKey.export({ type: "spki", format: "pem" }),
  };
  await assert.rejects(
    () =>
      runAttackJob(current, {
        trustedScopeConfig: trustConfig([
          entry("key-a", "reaper-platform", a.publicKey),
        ]),
      }),
    /must not supply its own verification keys/,
  );
  delete current.trustedScopeKeys;
  await assert.rejects(
    () => runAttackJob(current),
    /trust configuration is missing/,
  );
});

test("runner uses independent trusted key to verify a signed job end-to-end", async () => {
  const a = generateKeyPairSync("ed25519");
  const server = http.createServer((_req, res) => {
    res.statusCode = 200;
    res.end("authorized");
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const target = `http://127.0.0.1:${address.port}`;
  try {
    const signed = scope(target, a.privateKey);
    const current = job(target, signed);
    const result = await runAttackJob(current, {
      trustedScopeConfig: trustConfig([
        entry("key-a", "reaper-platform", a.publicKey),
      ]),
    });
    assert.equal(result.status, "COMPLETED");
    if (result.status === "COMPLETED") {
      assert.equal(result.result.attack?.requests, 1);
      assert.equal(result.result.attack?.signedScope?.issuer, "reaper-platform");
    }
  } finally {
    server.closeAllConnections?.();
    server.close();
    await once(server, "close");
  }
});
