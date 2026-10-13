import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { once } from "node:events";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  createSignedAuthorizationScope,
  FileAuditStore,
  FileExecutionJournalStore,
  FileScopeReplayStore,
  runAttack,
} from "../dist/index.js";

async function startServer() {
  const server = http.createServer((_req, res) => {
    res.statusCode = 200;
    res.end("{}");
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  return { server, target: `http://127.0.0.1:${address.port}` };
}

function scope(target, privateKey, nonce) {
  const now = Date.now();
  return createSignedAuthorizationScope(
    {
      version: 1,
      assessmentId: "commercial-assessment",
      issuer: "reaper-commercial-test",
      subject: "security-team",
      targetOrigins: [target],
      environment: "staging",
      permissions: ["read"],
      limits: {
        maxRequests: 3,
        maxCleanupRequests: 2,
        rateLimitPerSecond: 20,
        deadlineMs: 10_000,
      },
      issuedAt: new Date(now - 1000).toISOString(),
      expiresAt: new Date(now + 60_000).toISOString(),
      nonce,
    },
    "commercial-test-key",
    privateKey,
  );
}

function config(target) {
  return {
    attack: {
      allowedTargets: [target],
      requireSignedScope: true,
      authorization: {
        acknowledged: true,
        reference: "commercial-assessment",
        environment: "staging",
      },
      scenarios: [
        {
          id: "strict-read",
          title: "Strict commercial read",
          dimension: "session",
          steps: [
            {
              name: "read",
              path: "/resource",
              expect: { allowedStatuses: [200] },
            },
          ],
        },
      ],
    },
  };
}

test("strict commercial execution consumes signed scope nonce exactly once", async () => {
  const { server, target } = await startServer();
  const root = await mkdtemp(path.join(tmpdir(), "reaper-commercial-"));
  const keys = generateKeyPairSync("ed25519");
  try {
    const manifest = scope(target, keys.privateKey, "nonce-once");
    const journalStore = new FileExecutionJournalStore(
      path.join(root, "journal"),
    );
    const auditStore = new FileAuditStore(path.join(root, "audit"));
    const scopeReplayStore = new FileScopeReplayStore(
      path.join(root, "replay"),
    );
    const baseOptions = {
      workspaceId: "workspace-a",
      projectId: "project-a",
      scopeManifest: manifest,
      trustedScopeKeys: { "commercial-test-key": keys.publicKey },
      strictCommercial: true,
      journalStore,
      auditStore,
      scopeReplayStore,
    };

    const firstRunId = randomUUID();
    const first = await runAttack(target, config(target), {
      ...baseOptions,
      runId: firstRunId,
    });
    assert.equal(first.attack.runId, firstRunId);
    assert.equal((await journalStore.read(firstRunId)).status, "COMPLETED");
    assert.equal(await auditStore.verify(firstRunId), true);

    const secondRunId = randomUUID();
    await assert.rejects(
      runAttack(target, config(target), {
        ...baseOptions,
        runId: secondRunId,
      }),
      /already been consumed/,
    );
    assert.equal((await journalStore.read(secondRunId)).status, "FAILED");
    assert.equal(await auditStore.verify(secondRunId), true);
  } finally {
    server.closeAllConnections?.();
    server.close();
    await once(server, "close");
    await rm(root, { recursive: true, force: true });
  }
});

test("invalid signed scope is rejected before nonce consumption", async () => {
  const { server, target } = await startServer();
  const root = await mkdtemp(path.join(tmpdir(), "reaper-commercial-invalid-"));
  const keys = generateKeyPairSync("ed25519");
  try {
    const valid = scope(target, keys.privateKey, "nonce-after-invalid");
    const tampered = structuredClone(valid);
    tampered.payload.subject = "tampered";
    const journalStore = new FileExecutionJournalStore(
      path.join(root, "journal"),
    );
    const auditStore = new FileAuditStore(path.join(root, "audit"));
    const scopeReplayStore = new FileScopeReplayStore(
      path.join(root, "replay"),
    );
    const common = {
      workspaceId: "workspace-a",
      projectId: "project-a",
      trustedScopeKeys: { "commercial-test-key": keys.publicKey },
      strictCommercial: true,
      journalStore,
      auditStore,
      scopeReplayStore,
    };

    await assert.rejects(
      runAttack(target, config(target), {
        ...common,
        runId: randomUUID(),
        scopeManifest: tampered,
      }),
      /signature is invalid/,
    );

    const result = await runAttack(target, config(target), {
      ...common,
      runId: randomUUID(),
      scopeManifest: valid,
    });
    assert.equal(result.findings.length, 0);
  } finally {
    server.closeAllConnections?.();
    server.close();
    await once(server, "close");
    await rm(root, { recursive: true, force: true });
  }
});
