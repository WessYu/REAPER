import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { once } from "node:events";
import {
  createAttackJob,
  ENGINE_VERSION,
  runAttackJob,
} from "../dist/index.js";

async function startServer(handler) {
  const server = http.createServer(handler);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  return { server, target: `http://127.0.0.1:${address.port}` };
}

function job(target, overrides = {}) {
  const config = {
    attack: {
      allowedTargets: [target],
      authorization: {
        acknowledged: true,
        reference: "runner-test-assessment",
        environment: "staging",
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
      },
      scenarios: [
        {
          id: "runner-read",
          title: "Read a known synthetic resource",
          dimension: "session",
          steps: [
            {
              name: "authorized read",
              path: "/private",
              expect: { allowedStatuses: [200] },
            },
          ],
        },
      ],
    },
  };
  return createAttackJob({
    target,
    config,
    authorization: config.attack.authorization,
    limits: {
      deadlineMs: 5_000,
      cleanupGraceMs: 2_000,
      memoryMb: 128,
      maxOutputBytes: 1_000_000,
    },
    engineVersion: ENGINE_VERSION,
    ...overrides,
  });
}

test("attack job runs in a bounded child process and returns its exit status", async () => {
  const { server, target } = await startServer((_req, res) => {
    res.statusCode = 200;
    res.end("ok");
  });
  try {
    const current = job(target);
    let targetReads = 0;
    Object.defineProperty(current, "target", {
      enumerable: true,
      get() {
        targetReads++;
        return targetReads === 1 ? target : "https://escape.example.test";
      },
    });
    const result = await runAttackJob(current);
    assert.equal(targetReads, 1);
    assert.equal(result.status, "COMPLETED");
    if (result.status !== "COMPLETED") return;
    assert.equal(result.exitCode, 0);
    assert.equal(result.result.attack?.target, target);
    assert.equal(result.result.attack?.requests, 1);
    assert.equal(result.result.attack?.runId, current.runId);
    assert.equal(result.result.attack?.engineVersion, ENGINE_VERSION);
  } finally {
    server.closeAllConnections?.();
    server.close();
    await once(server, "close");
  }
});

test("runner exports only referenced secrets and never returns their values", async () => {
  const sentinel = "SUPER_SECRET_RUNNER_TEST_650218";
  process.env.REAPER_RUNNER_TEST_TOKEN = sentinel;
  process.env.REAPER_UNRELATED_SECRET = "DO_NOT_COPY_TO_RUNNER";
  let sawToken = false;
  const { server, target } = await startServer((req, res) => {
    sawToken = req.headers.authorization === `Bearer ${sentinel}`;
    res.statusCode = sawToken ? 200 : 401;
    res.end("ok");
  });
  const current = job(target);
  current.config.attack.identities = {
    testUser: { tokenEnv: "REAPER_RUNNER_TEST_TOKEN" },
  };
  current.config.attack.scenarios[0].steps[0].actor = "testUser";
  try {
    const result = await runAttackJob(current);
    assert.equal(result.status, "COMPLETED");
    assert.equal(sawToken, true);
    assert.equal(JSON.stringify(result).includes(sentinel), false);
    assert.equal(
      JSON.stringify(result).includes("DO_NOT_COPY_TO_RUNNER"),
      false,
    );
  } finally {
    delete process.env.REAPER_RUNNER_TEST_TOKEN;
    delete process.env.REAPER_UNRELATED_SECRET;
    server.closeAllConnections?.();
    server.close();
    await once(server, "close");
  }
});

test("runner deadline cancels a slow worker and reports its outcome", async () => {
  const { server, target } = await startServer((_req, res) => {
    setTimeout(() => res.end("late"), 5_000);
  });
  const current = job(target, {
    limits: {
      deadlineMs: 500,
      cleanupGraceMs: 2_000,
      memoryMb: 128,
      maxOutputBytes: 1_000_000,
    },
  });
  current.config.attack.timeoutMs = 10_000;
  try {
    const result = await runAttackJob(current);
    assert.equal(result.status, "INTERRUPTED");
    if (result.status === "INTERRUPTED") {
      assert.equal(result.reason, "deadline-exceeded");
      assert.equal(result.exitCode, 0);
    }
  } finally {
    server.closeAllConnections?.();
    server.close();
    await once(server, "close");
  }
});

test("runner rejects mismatched job authorization and enforces report output cap", async () => {
  const { server, target } = await startServer((_req, res) => {
    res.statusCode = 200;
    res.end("ok");
  });
  try {
    const mismatched = job(target);
    mismatched.authorization = {
      ...mismatched.authorization,
      reference: "different-assessment",
    };
    await assert.rejects(runAttackJob(mismatched), /does not match/);
    const oversizedJob = job(target);
    oversizedJob.config.attack.scenarios[0].title = "x".repeat(
      5 * 1024 * 1024 + 1,
    );
    await assert.rejects(runAttackJob(oversizedJob), /5 MiB input limit/);

    const tooSmall = job(target, {
      limits: {
        deadlineMs: 5_000,
        cleanupGraceMs: 2_000,
        memoryMb: 128,
        maxOutputBytes: 1_024,
      },
    });
    tooSmall.config.attack.maxRequests = 30;
    tooSmall.config.attack.rateLimitPerSecond = 20;
    tooSmall.config.attack.scenarios[0].steps = Array.from(
      { length: 20 },
      (_, index) => ({
        name: `read ${index}`,
        path: "/private",
        expect: { allowedStatuses: [200] },
      }),
    );
    const result = await runAttackJob(tooSmall);
    assert.equal(result.status, "FAILED");
    if (result.status === "FAILED") assert.equal(result.reason, "report-limit");
  } finally {
    server.closeAllConnections?.();
    server.close();
    await once(server, "close");
  }
});

test("runner cancellation reaches engine and allows declared cleanup", async () => {
  let resourceExists = false;
  const { server, target } = await startServer((req, res) => {
    if (req.method === "POST") {
      resourceExists = true;
      return;
    }
    if (req.method === "DELETE") {
      resourceExists = false;
      res.statusCode = 204;
      res.end();
      return;
    }
    res.statusCode = 200;
    res.end("ok");
  });
  const controller = new AbortController();
  const current = job(target);
  current.config.attack.allowMutations = true;
  current.config.attack.maxCleanupRequests = 1;
  current.config.attack.scenarios[0].steps[0].method = "POST";
  current.config.attack.scenarios[0].cleanup = [
    { name: "remove test resource", method: "DELETE", path: "/resource" },
  ];
  const pending = runAttackJob(current, { signal: controller.signal });
  setTimeout(() => controller.abort(), 400);
  try {
    const result = await pending;
    assert.equal(result.status, "INTERRUPTED");
    assert.equal(resourceExists, false);
    if (result.status === "INTERRUPTED") {
      assert.equal(result.reason, "cancelled");
      assert.equal(result.exitCode, 0);
      assert.equal(result.result?.attack?.cleanupRequests, 1);
    }
  } finally {
    server.closeAllConnections?.();
    server.close();
    await once(server, "close");
  }
});
