import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { once } from "node:events";
import { randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  createAttackJob,
  ENGINE_VERSION,
  FileAuditStore,
  FileExecutionJournalStore,
  ProcessIsolationProvider,
  recoverAttackRun,
  runAttackJob,
} from "../dist/index.js";

async function server(handler) {
  const instance = http.createServer(handler);
  instance.listen(0, "127.0.0.1");
  await once(instance, "listening");
  const address = instance.address();
  assert.ok(address && typeof address !== "string");
  return { instance, target: `http://127.0.0.1:${address.port}` };
}

async function createRecoveryRecord(store, target, overrides = {}) {
  const runId = randomUUID();
  const createdAt =
    overrides.createdAt ?? new Date().toISOString();
  await store.create({
    version: 1,
    runId,
    workspaceId: "workspace-a",
    projectId: "project-a",
    assessmentId: "assessment-a",
    targetOrigin: target,
    environment: "staging",
    allowPrivateNetwork: false,
    timeoutMs: 1000,
    rateLimitPerSecond: 20,
    maxCleanupRequests: 5,
    createdAt,
    status: "RUNNING",
    cleanups: [
      {
        id: "cleanup-1",
        scenarioId: "recovery-scenario",
        stepName: "delete resource",
        method: "DELETE",
        path: "/resource",
        allowedStatuses: [204, 404],
        attempts: 0,
        status: "PENDING",
        plannedAt: createdAt,
        updatedAt: createdAt,
      },
    ],
  });
  return runId;
}

test("recovery retries failed cleanup and treats explicit 404 as idempotent success", async () => {
  let cleanupStatus = 500;
  const { instance, target } = await server((req, res) => {
    if (req.method === "DELETE" && req.url === "/resource") {
      res.statusCode = cleanupStatus;
      res.end();
      return;
    }
    res.statusCode = 404;
    res.end();
  });
  const root = await mkdtemp(path.join(tmpdir(), "reaper-recovery-"));
  try {
    const journal = new FileExecutionJournalStore(path.join(root, "journal"));
    const audit = new FileAuditStore(path.join(root, "audit"));
    const runId = await createRecoveryRecord(journal, target);

    const failed = await recoverAttackRun(journal, runId, {
      auditStore: audit,
      claimStaleMs: 1000,
    });
    assert.equal(failed.status, "CLEANUP_FAILED");
    assert.equal(failed.failed, 1);
    assert.equal((await journal.read(runId)).status, "CLEANUP_FAILED");

    cleanupStatus = 404;
    const retried = await recoverAttackRun(journal, runId, {
      auditStore: audit,
      claimStaleMs: 1000,
    });
    assert.equal(retried.status, "COMPLETED");
    assert.equal(retried.succeeded, 1);
    const record = await journal.read(runId);
    assert.equal(record.status, "COMPLETED");
    assert.equal(record.cleanups[0].status, "SUCCEEDED");
    assert.equal(record.cleanups[0].attempts, 2);
    assert.equal(await audit.verify(runId), true);

    await assert.rejects(
      recoverAttackRun(journal, runId, { auditStore: audit }),
      /not in a recoverable state/,
    );
  } finally {
    instance.closeAllConnections?.();
    instance.close();
    await once(instance, "close");
    await rm(root, { recursive: true, force: true });
  }
});

test("stale recovery requires explicit operator approval", async () => {
  const { instance, target } = await server((_req, res) => {
    res.statusCode = 204;
    res.end();
  });
  const root = await mkdtemp(path.join(tmpdir(), "reaper-recovery-stale-"));
  try {
    const journal = new FileExecutionJournalStore(path.join(root, "journal"));
    const audit = new FileAuditStore(path.join(root, "audit"));
    const runId = await createRecoveryRecord(journal, target, {
      createdAt: new Date(Date.now() - 8 * 24 * 60 * 60_000).toISOString(),
    });
    await assert.rejects(
      recoverAttackRun(journal, runId, { auditStore: audit }),
      /stale/,
    );
    const recovered = await recoverAttackRun(journal, runId, {
      auditStore: audit,
      allowStale: true,
    });
    assert.equal(recovered.status, "COMPLETED");
  } finally {
    instance.closeAllConnections?.();
    instance.close();
    await once(instance, "close");
    await rm(root, { recursive: true, force: true });
  }
});

test("write-ahead journal survives worker SIGKILL and recovery performs only declared cleanup", async () => {
  let resourceExists = false;
  let child;
  const baseProvider = new ProcessIsolationProvider();
  const isolationProvider = {
    name: "test-capturing-process",
    capabilities: baseProvider.capabilities,
    spawn(input) {
      child = baseProvider.spawn(input);
      return child;
    },
  };
  const { instance, target } = await server((req, res) => {
    if (req.method === "POST" && req.url === "/resource") {
      resourceExists = true;
      res.statusCode = 201;
      res.end("{}");
      child?.kill("SIGKILL");
      return;
    }
    if (req.method === "DELETE" && req.url === "/resource") {
      resourceExists = false;
      res.statusCode = 204;
      res.end();
      return;
    }
    res.statusCode = 404;
    res.end();
  });
  const stateDirectory = await mkdtemp(
    path.join(tmpdir(), "reaper-runner-crash-state-"),
  );
  try {
    const config = {
      attack: {
        allowedTargets: [target],
        authorization: {
          acknowledged: true,
          reference: "crash-recovery-assessment",
          environment: "staging",
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
        },
        allowMutations: true,
        maxCleanupRequests: 2,
        scenarios: [
          {
            id: "crash-after-mutation",
            title: "Crash after a synthetic mutation",
            dimension: "business-logic",
            steps: [
              {
                name: "create resource",
                path: "/resource",
                method: "POST",
                expect: { allowedStatuses: [201] },
              },
            ],
            cleanup: [
              {
                name: "delete resource",
                path: "/resource",
                method: "DELETE",
                expect: { allowedStatuses: [204, 404] },
              },
            ],
          },
        ],
      },
    };
    const current = createAttackJob({
      target,
      config,
      authorization: config.attack.authorization,
      workspaceId: "workspace-a",
      projectId: "project-a",
      limits: {
        deadlineMs: 5000,
        cleanupGraceMs: 100,
        memoryMb: 128,
        maxOutputBytes: 1_000_000,
      },
      engineVersion: ENGINE_VERSION,
    });
    const outcome = await runAttackJob(current, {
      stateDirectory,
      isolationProvider,
    });
    assert.equal(outcome.status, "FAILED");
    assert.equal(resourceExists, true);

    const journal = new FileExecutionJournalStore(
      path.join(stateDirectory, "journal"),
    );
    const audit = new FileAuditStore(path.join(stateDirectory, "audit"));
    const crashed = await journal.read(current.runId);
    assert.ok(["RUNNING", "CLEANING"].includes(crashed.status));
    assert.equal(crashed.cleanups.length, 1);
    assert.equal(crashed.cleanups[0].method, "DELETE");
    assert.equal(crashed.cleanups[0].path, "/resource");

    const recovered = await recoverAttackRun(journal, current.runId, {
      auditStore: audit,
    });
    assert.equal(recovered.status, "COMPLETED");
    assert.equal(resourceExists, false);
    assert.equal(await audit.verify(current.runId), true);
  } finally {
    instance.closeAllConnections?.();
    instance.close();
    await once(instance, "close");
    await rm(stateDirectory, { recursive: true, force: true });
  }
});


test("concurrent recovery claims a cleanup at most once", async () => {
  let deletes = 0;
  const { instance, target } = await server((req, res) => {
    if (req.method === "DELETE" && req.url === "/resource") {
      deletes++;
      setTimeout(() => {
        res.statusCode = 204;
        res.end();
      }, 100);
      return;
    }
    res.statusCode = 404;
    res.end();
  });
  const root = await mkdtemp(path.join(tmpdir(), "reaper-recovery-race-"));
  try {
    const journal = new FileExecutionJournalStore(path.join(root, "journal"));
    const audit = new FileAuditStore(path.join(root, "audit"));
    const runId = await createRecoveryRecord(journal, target);
    const results = await Promise.all([
      recoverAttackRun(journal, runId, {
        auditStore: audit,
        claimStaleMs: 10_000,
      }),
      recoverAttackRun(journal, runId, {
        auditStore: audit,
        claimStaleMs: 10_000,
      }),
    ]);
    assert.equal(deletes, 1);
    assert.ok(results.some((result) => result.status === "COMPLETED"));
    assert.ok(
      results.some(
        (result) =>
          result.status === "INCOMPLETE" || result.status === "COMPLETED",
      ),
    );
    assert.equal((await journal.read(runId)).status, "COMPLETED");
    assert.equal(await audit.verify(runId), true);
  } finally {
    instance.closeAllConnections?.();
    instance.close();
    await once(instance, "close");
    await rm(root, { recursive: true, force: true });
  }
});
