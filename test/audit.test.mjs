import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { FileAuditStore, verifyAuditChain } from "../dist/index.js";

test("persistent audit trail is hash chained and sanitizes line injection", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "reaper-audit-"));
  const runId = randomUUID();
  try {
    const store = new FileAuditStore(root);
    const first = await store.append(runId, {
      type: "RUN_CREATED",
      data: {
        target: "https://preview.example.test\nFORGED_EVENT",
      },
    });
    const second = await store.append(runId, {
      type: "RUN_STARTED",
      data: { workspaceId: "workspace-a" },
    });
    assert.equal(first.sequence, 1);
    assert.equal(second.sequence, 2);
    assert.equal(second.previousHash, first.eventHash);
    assert.equal(await verifyAuditChain(store, runId), true);
    const raw = await readFile(path.join(root, `${runId}.audit.jsonl`), "utf8");
    assert.equal(raw.includes("\nFORGED_EVENT"), false);
    assert.ok(raw.includes("FORGED_EVENT"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("audit verification detects event tampering", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "reaper-audit-tamper-"));
  const runId = randomUUID();
  try {
    const store = new FileAuditStore(root);
    await store.append(runId, { type: "RUN_CREATED", data: { target: "a" } });
    await store.append(runId, { type: "RUN_STARTED", data: { target: "a" } });
    const file = path.join(root, `${runId}.audit.jsonl`);
    const lines = (await readFile(file, "utf8")).trimEnd().split("\n");
    const first = JSON.parse(lines[0]);
    first.data.target = "b";
    lines[0] = JSON.stringify(first);
    await writeFile(file, lines.join("\n") + "\n");
    await assert.rejects(store.verify(runId), /integrity verification failed/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("audit appends are serialized for one run", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "reaper-audit-concurrent-"));
  const runId = randomUUID();
  try {
    const store = new FileAuditStore(root);
    await Promise.all(
      Array.from({ length: 12 }, (_, index) =>
        store.append(runId, {
          type: "REQUEST_EXECUTED",
          data: { index },
        }),
      ),
    );
    const events = await store.read(runId);
    assert.equal(events.length, 12);
    assert.deepEqual(
      events.map((event) => event.sequence),
      Array.from({ length: 12 }, (_, index) => index + 1),
    );
    assert.equal(await store.verify(runId), true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("audit head anchor detects valid-prefix tail truncation", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "reaper-audit-truncate-"));
  const runId = randomUUID();
  try {
    const store = new FileAuditStore(root);
    await store.append(runId, { type: "RUN_CREATED", data: {} });
    await store.append(runId, { type: "RUN_STARTED", data: {} });
    await store.append(runId, { type: "RUN_COMPLETED", data: {} });
    const file = path.join(root, `${runId}.audit.jsonl`);
    const lines = (await readFile(file, "utf8")).trimEnd().split("\n");
    await writeFile(file, lines.slice(0, -1).join("\n") + "\n");
    await assert.rejects(store.verify(runId), /truncation|head mismatch/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
