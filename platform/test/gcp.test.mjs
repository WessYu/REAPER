import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as signData } from "node:crypto";
import { GcpKmsScopeSigner } from "../dist/gcp-kms-signer.js";
import { CloudRunJobClient } from "../dist/cloud-run-job.js";
import { verifyAuthorizationScope } from "../../dist/index.js";

function crc32c(input) {
  let crc = 0xffffffff;
  for (const byte of input) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++)
      crc = (crc >>> 1) ^ (crc & 1 ? 0x82f63b78 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

test("Cloud KMS signer produces an engine-verifiable Ed25519 scope", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const keyVersionName =
    "projects/reaper-staging/locations/southamerica-east1/keyRings/reaper/cryptoKeys/authorization-scope/cryptoKeyVersions/1";

  const fetchImpl = async (url, init = {}) => {
    if (String(url).endsWith("/publicKey")) {
      return Response.json({
        name: keyVersionName,
        algorithm: "EC_SIGN_ED25519",
        pem,
      });
    }
    assert.equal(
      String(url),
      `https://cloudkms.googleapis.com/v1/${keyVersionName}:asymmetricSign`,
    );
    const body = JSON.parse(String(init.body));
    const data = Buffer.from(body.data, "base64");
    assert.equal(Number(body.dataCrc32c), crc32c(data));
    const signature = signData(null, data, privateKey);
    return Response.json({
      name: keyVersionName,
      signature: signature.toString("base64"),
      signatureCrc32c: String(crc32c(signature)),
      verifiedDataCrc32c: true,
    });
  };

  const signer = await GcpKmsScopeSigner.create(
    {
      keyVersionName,
      keyId: "gcp-kms-test-v1",
    },
    {
      fetchImpl,
      accessTokenProvider: async () => "synthetic-access-token",
    },
  );

  const issuedAt = new Date();
  const payload = {
    version: 1,
    assessmentId: "assessment-test",
    issuer: "reaper-platform",
    subject: "workspace:test:run:test",
    targetOrigins: ["https://preview.example.test"],
    environment: "staging",
    permissions: ["read"],
    limits: {
      maxRequests: 10,
      maxCleanupRequests: 5,
      rateLimitPerSecond: 2,
      deadlineMs: 60_000,
    },
    issuedAt: issuedAt.toISOString(),
    expiresAt: new Date(issuedAt.getTime() + 120_000).toISOString(),
    nonce: "nonce-test",
  };
  const scope = await signer.sign(payload);
  const verified = verifyAuthorizationScope(
    scope,
    { [scope.keyId]: pem },
    {
      target: "https://preview.example.test",
      environment: "staging",
      reference: "assessment-test",
      now: issuedAt.getTime() + 1_000,
    },
  );
  assert.equal(verified.nonce, "nonce-test");
});

test("Cloud Run client executes one task with bounded overrides", async () => {
  let request;
  const client = new CloudRunJobClient({
    projectId: "reaper-staging",
    region: "southamerica-east1",
    jobName: "reaper-runner",
    accessTokenProvider: async () => "synthetic-access-token",
    fetchImpl: async (url, init) => {
      request = { url: String(url), init };
      return Response.json({
        name: "projects/reaper-staging/locations/southamerica-east1/operations/op-1",
      });
    },
  });
  const result = await client.execute({
    jobId: "30000000-0000-4000-8000-000000000001",
    workerId: "cloud-dispatcher-test",
    timeoutMs: 120_000,
  });
  assert.match(result.operationName, /operations\/op-1$/);
  const body = JSON.parse(String(request.init.body));
  assert.equal(body.overrides.taskCount, 1);
  assert.equal(
    body.overrides.containerOverrides[0].env[0].name,
    "REAPER_EXECUTION_JOB_ID",
  );
  assert.equal(
    body.overrides.containerOverrides[0].env[0].value,
    "30000000-0000-4000-8000-000000000001",
  );
  assert.equal(
    body.overrides.containerOverrides[0].env[1].name,
    "REAPER_EXECUTION_WORKER_ID",
  );
  assert.equal(body.overrides.timeout, "180s");
});
