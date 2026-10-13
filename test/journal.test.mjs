import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { FileExecutionJournalStore } from "../dist/index.js";

function record(runId = randomUUID()) {
  const now = new Date().toISOString();
  return {
    version: 1,
    runId,
    workspaceId: "workspace-a",
    projectId: "project-a",
    assessmentId: "assessment-a",
    targetOrigin: "https://preview.example.test",
    environment: "staging",
    allowPrivateNetwork: false,
    timeoutMs: 5000,
    rateLimitPerSecond: 3,
    maxCleanupRequests: 10,
    createdAt: now,
    status: "PENDING",
  };
}

test("execution journal persists updates and lists recoverable runs", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "reaper-journal-"));
  try {
    const store = new FileExecutionJournalStore(root);
    const created = await store.create(record());
    assert.equal(created.status, "PENDING");
    assert.match(created.integrity, /^[a-f0-9]{64}$/);

    const updated = await store.update(created.runId, (current) => {
      current.status = "RUNNING";
      current.cleanups.push({
        id: "cleanup-1",
        scenarioId: "scenario-1",
        stepName: "delete-resource",
        method: "DELETE",
        path: "/api/test/123",
        allowedStatuses: [204, 404],
        attempts: 0,
        status: "PENDING",
        plannedAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });
    });
    assert.equal(updated.status, "RUNNING");
    assert.equal(updated.cleanups.length, 1);
    assert.deepEqual(
      (await store.listRecoverable()).map((item) => item.runId),
      [created.runId],
    );

    const completed = await store.update(created.runId, (current) => {
      current.status = "COMPLETED";
    });
    assert.equal(completed.status, "COMPLETED");
    assert.deepEqual(await store.listRecoverable(), []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("execution journal rejects tampering and partial/corrupted JSON", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "reaper-journal-tamper-"));
  try {
    const store = new FileExecutionJournalStore(root);
    const created = await store.create(record());
    const file = path.join(root, `${created.runId}.json`);
    const parsed = JSON.parse(await readFile(file, "utf8"));
    parsed.workspaceId = "workspace-b";
    await writeFile(file, JSON.stringify(parsed));
    await assert.rejects(
      store.read(created.runId),
      /integrity verification failed/,
    );

    await writeFile(file, '{"version":1');
    await assert.rejects(store.read(created.runId), /invalid JSON/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("execution journal rejects symlinked run files", async (t) => {
  if (process.platform === "win32") {
    t.skip("symlink creation is privilege-dependent on Windows");
    return;
  }
  const root = await mkdtemp(path.join(tmpdir(), "reaper-journal-link-"));
  const outside = path.join(
    root,
    "..",
    `reaper-journal-outside-${randomUUID()}`,
  );
  try {
    const current = record();
    await writeFile(outside, "{}");
    await symlink(outside, path.join(root, `${current.runId}.json`));
    const store = new FileExecutionJournalStore(root);
    await assert.rejects(store.read(current.runId), /symbolic links/);
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(outside, { force: true });
  }
});

test("journal update removes an abandoned lock from a dead process", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "reaper-journal-lock-"));
  try {
    const store = new FileExecutionJournalStore(root);
    const created = await store.create(record());
    await writeFile(path.join(root, `${created.runId}.lock`), "2147483647");
    const updated = await store.update(created.runId, (current) => {
      current.status = "RUNNING";
    });
    assert.equal(updated.status, "RUNNING");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
