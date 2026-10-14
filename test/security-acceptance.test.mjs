import test from "node:test";
import assert from "node:assert/strict";
import { runLocalTimingSqliLab } from "../dist/index.js";

const experiment = {
  name: "acceptance",
  positive: "P",
  negative: "N",
  expectedDelayMs: 80,
};

function setup(fetchImpl, extra = {}) {
  return runLocalTimingSqliLab("http://127.0.0.1/lab", {
    phpSessionId: "test-session",
    samples: 3,
    timeoutMs: 1000,
    baselinePayload: "B",
    experiments: [experiment],
    fetchImpl,
    ...extra,
  });
}

test("acceptance: rejected remote URLs never reach the transport", async () => {
  const rejected = [
    "https://example.com/lab",
    "http://169.254.169.254/latest/meta-data/",
    "http://10.0.0.1/lab",
    "http://127.0.0.2/lab",
    "file:///etc/passwd",
    "http://localhost.example.com/lab",
    "http://localhost@evil.example/lab",
    "http://127.0.0.1/lab?token=hidden",
  ];
  let requests = 0;
  for (const target of rejected) {
    await assert.rejects(
      runLocalTimingSqliLab(target, {
        phpSessionId: "test-session",
        fetchImpl: async () => {
          requests++;
          return new Response("OK");
        },
      }),
    );
  }
  assert.equal(requests, 0);
});

test("acceptance: HTTP errors are inconclusive", async () => {
  for (const status of [401, 403, 404, 429, 500]) {
    const result = await setup(async () => new Response("error", { status }));
    assert.equal(result.confirmed, 0);
    assert.equal(result.conclusion, "INCONCLUSIVE");
  }
});

test("acceptance: wrong body marker is inconclusive", async () => {
  const result = await setup(
    async () => new Response("login page", { status: 200 }),
    { responseMarker: "SQL Injection" },
  );
  assert.equal(result.confirmed, 0);
  assert.equal(result.experiments[0].confidence, "INCONCLUSIVE");
});

test("acceptance: bounded and alternated requests", async () => {
  const sequence = [];
  const result = await setup(async (input) => {
    sequence.push(new URL(String(input)).searchParams.get("id"));
    return new Response("SQL Injection", { status: 200 });
  });
  assert.deepEqual(sequence, ["B", "B", "B", "N", "P", "P", "N", "N", "P"]);
  assert.equal(result.confirmed, 0);
});

test("acceptance: reject invalid definition before requests", async () => {
  let called = false;
  await assert.rejects(
    setup(
      async () => {
        called = true;
        return new Response("OK");
      },
      {
        experiments: [{ ...experiment, expectedDelayMs: 10001 }],
      },
    ),
    /invalid/,
  );
  assert.equal(called, false);
});
