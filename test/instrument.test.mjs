import { test } from "node:test";
import assert from "node:assert/strict";
import {
  currentReaperTraceId,
  runWithReaperTrace,
  reaperTraceMiddleware,
} from "../dist/index.js";

test("runtime trace context propagates through async work without accepting arbitrary IDs", async () => {
  const traceId = "123e4567-e89b-42d3-a456-426614174000";
  await runWithReaperTrace({ "x-reaper-trace-id": traceId }, async () => {
    await Promise.resolve();
    assert.equal(currentReaperTraceId(), traceId);
  });
  assert.equal(currentReaperTraceId(), undefined);
  runWithReaperTrace(
    { "x-reaper-trace-id": "attacker-controlled-freeform" },
    () => assert.equal(currentReaperTraceId(), undefined),
  );
});

test("Express-style trace middleware exposes the active REAPER trace to downstream handlers", async () => {
  const traceId = "123e4567-e89b-42d3-a456-426614174000";
  await new Promise((resolve, reject) => {
    reaperTraceMiddleware(
      { headers: { "x-reaper-trace-id": traceId } },
      {},
      (error) => {
        if (error) {
          reject(error);
          return;
        }
        try {
          assert.equal(currentReaperTraceId(), traceId);
          resolve();
        } catch (assertion) {
          reject(assertion);
        }
      },
    );
  });
});
