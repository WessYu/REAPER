import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  FileScopeReplayStore,
  InMemoryScopeReplayStore,
} from "../dist/index.js";

function input() {
  return {
    issuer: "reaper-test-authority",
    assessmentId: "assessment-42",
    nonce: "nonce-42",
    targetOrigin: "https://preview.example.test",
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
  };
}

test("in-memory replay store accepts once and rejects reuse", async () => {
  const store = new InMemoryScopeReplayStore();
  assert.equal(await store.consume(input()), true);
  assert.equal(await store.consume(input()), false);
});

test("filesystem replay store is atomic under concurrent consumption", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "reaper-replay-"));
  try {
    const store = new FileScopeReplayStore(root);
    const results = await Promise.all([
      store.consume(input()),
      store.consume(input()),
      store.consume(input()),
      store.consume(input()),
    ]);
    assert.equal(results.filter(Boolean).length, 1);
    assert.equal(results.filter((value) => !value).length, 3);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("filesystem replay store collects expired records in a bounded pass", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "reaper-replay-gc-"));
  try {
    const store = new FileScopeReplayStore(root);
    const expired = {
      ...input(),
      nonce: "expired",
      expiresAt: new Date(Date.now() - 1000).toISOString(),
    };
    const fresh = { ...input(), nonce: "fresh" };
    assert.equal(await store.consume(expired), true);
    assert.equal(await store.consume(fresh), true);
    assert.equal(await store.collectExpired(Date.now(), 1), 1);
    assert.equal(await store.consume(expired), true);
    assert.equal(await store.consume(fresh), false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
