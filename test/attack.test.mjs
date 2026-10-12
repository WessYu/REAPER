import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { once } from "node:events";
import { runAttack, validateConfig } from "../dist/index.js";

async function server(handler) {
  const instance = http.createServer(handler);
  instance.listen(0, "127.0.0.1");
  await once(instance, "listening");
  const address = instance.address();
  if (!address || typeof address === "string") throw new Error("No test port.");
  return {
    instance,
    origin: `http://127.0.0.1:${address.port}`,
  };
}

test("attack mode confirms cross-user access only with actor and known resource", async () => {
  const deleted = [];
  const { instance, origin } = await server((req, res) => {
    if (req.method === "GET" && req.url === "/orders/order-b") {
      assert.equal(req.headers.authorization, "Bearer user-a-token");
      res.statusCode = 200;
      res.end(JSON.stringify({ id: "order-b", owner: "user-b" }));
      return;
    }
    if (req.method === "DELETE" && req.url === "/orders/order-b") {
      deleted.push(req.url);
      res.statusCode = 204;
      res.end();
      return;
    }
    res.statusCode = 404;
    res.end();
  });
  process.env.REAPER_ATTACK_USER_A = "user-a-token";
  try {
    const result = await runAttack(origin, {
      attack: {
        allowedTargets: [origin],
        authorization: {
          acknowledged: true,
          reference: "test-suite",
          environment: "staging",
        },
        allowMutations: true,
        maxRequests: 5,
        rateLimitPerSecond: 20,
        identities: {
          userA: { tokenEnv: "REAPER_ATTACK_USER_A" },
        },
        scenarios: [
          {
            id: "cross-user-order",
            title: "User A must not read User B order",
            dimension: "ownership",
            steps: [
              {
                name: "cross-user read",
                path: "/orders/order-b",
                actor: "userA",
                resource: "order:order-b:owner:user-b",
                expect: { deniedStatuses: [403, 404] },
              },
            ],
            cleanup: [
              {
                name: "cleanup order",
                path: "/orders/order-b",
                method: "DELETE",
                actor: "userA",
              },
            ],
          },
        ],
      },
    });
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].ruleId, "REAPER-ATTACK-001");
    assert.equal(result.findings[0].confidence, "CONFIRMED");
    assert.equal(result.findings[0].category, "Offensive Validation");
    assert.equal(result.attack.confirmed.length, 1);
    assert.ok(
      result.graph.nodes.some(
        (node) => node.kind === "principal" && node.label === "userA",
      ),
    );
    assert.ok(!JSON.stringify(result).includes("user-a-token"));
    assert.deepEqual(deleted, ["/orders/order-b"]);
  } finally {
    delete process.env.REAPER_ATTACK_USER_A;
    instance.close();
    await once(instance, "close");
  }
});

test("attack mode treats expected denial as passed, not a finding", async () => {
  const { instance, origin } = await server((_req, res) => {
    res.statusCode = 403;
    res.end("denied");
  });
  process.env.REAPER_ATTACK_USER_A = "user-a-token";
  try {
    const result = await runAttack(origin, {
      attack: {
        allowedTargets: [origin],
        authorization: {
          acknowledged: true,
          reference: "test-suite",
          environment: "staging",
        },
        identities: {
          userA: { tokenEnv: "REAPER_ATTACK_USER_A" },
        },
        scenarios: [
          {
            id: "denied-order",
            title: "Cross-user read stays denied",
            dimension: "ownership",
            steps: [
              {
                name: "read",
                path: "/orders/order-b",
                actor: "userA",
                resource: "order:order-b:owner:user-b",
                expect: { deniedStatuses: [403, 404] },
              },
            ],
          },
        ],
      },
    });
    assert.equal(result.findings.length, 0);
    assert.equal(result.diagnostics.length, 0);
    assert.equal(result.attack.audit[0].outcome, "passed");
  } finally {
    delete process.env.REAPER_ATTACK_USER_A;
    instance.close();
    await once(instance, "close");
  }
});

test("attack config requires explicit authorization evidence and confirmation context", () => {
  assert.throws(
    () =>
      validateConfig({
        attack: {
          allowedTargets: ["https://example.test"],
          authorization: {
            acknowledged: false,
            reference: "ticket",
            environment: "staging",
          },
          scenarios: [],
        },
      }),
    /acknowledged/,
  );

  assert.throws(
    () =>
      validateConfig({
        attack: {
          allowedTargets: ["https://example.test"],
          authorization: {
            acknowledged: true,
            reference: "ticket",
            environment: "staging",
          },
          identities: { userA: { tokenEnv: "USER_A_TOKEN" } },
          scenarios: [
            {
              id: "missing-resource",
              title: "Missing resource proof",
              dimension: "ownership",
              steps: [
                {
                  name: "read",
                  path: "/orders/1",
                  actor: "userA",
                  expect: { deniedStatuses: [403] },
                },
              ],
            },
          ],
        },
      }),
    /known test resource/,
  );
});

test("attack mode refuses targets outside the exact allowlist", async () => {
  await assert.rejects(
    runAttack("https://example.com", {
      attack: {
        allowedTargets: ["https://example.org"],
        authorization: {
          acknowledged: true,
          reference: "test-suite",
          environment: "staging",
        },
        scenarios: [
          {
            id: "blocked",
            title: "Blocked target",
            dimension: "session",
            steps: [{ name: "head", path: "/", method: "HEAD" }],
          },
        ],
      },
    }),
    /allowlist/,
  );
});

test("attack mode opens a circuit breaker on repeated server errors", async () => {
  let requests = 0;
  const { instance, origin } = await server((_req, res) => {
    requests++;
    res.statusCode = 503;
    res.end("unavailable");
  });
  try {
    const result = await runAttack(origin, {
      attack: {
        allowedTargets: [origin],
        authorization: {
          acknowledged: true,
          reference: "test-suite",
          environment: "staging",
        },
        maxConsecutiveServerErrors: 2,
        maxRequests: 5,
        rateLimitPerSecond: 20,
        scenarios: [
          {
            id: "breaker",
            title: "Stop on server degradation",
            dimension: "session",
            steps: [
              { name: "one", path: "/one" },
              { name: "two", path: "/two" },
              { name: "three", path: "/three" },
            ],
          },
        ],
      },
    });
    assert.equal(requests, 2);
    assert.ok(
      result.diagnostics.some((item) => /Circuit breaker/.test(item.message)),
    );
  } finally {
    instance.close();
    await once(instance, "close");
  }
});

test("attack mode enforces mutation gates at runtime and in cleanup", async () => {
  const { instance, origin } = await server((_req, res) => {
    res.statusCode = 204;
    res.end();
  });
  try {
    await assert.rejects(
      runAttack(origin, {
        attack: {
          allowedTargets: [origin],
          authorization: {
            acknowledged: true,
            reference: "test-suite",
            environment: "staging",
          },
          scenarios: [
            {
              id: "cleanup-mutation",
              title: "Cleanup mutation must be explicitly enabled",
              dimension: "session",
              steps: [{ name: "read", path: "/" }],
              cleanup: [
                {
                  name: "delete",
                  path: "/resource",
                  method: "DELETE",
                },
              ],
            },
          ],
        },
      }),
      /allowMutations/,
    );
  } finally {
    instance.close();
    await once(instance, "close");
  }
});

test("attack mode blocks production mutation even for direct API callers", async () => {
  const { instance, origin } = await server((_req, res) => {
    res.statusCode = 204;
    res.end();
  });
  try {
    await assert.rejects(
      runAttack(origin, {
        attack: {
          allowedTargets: [origin],
          authorization: {
            acknowledged: true,
            reference: "test-suite",
            environment: "production",
          },
          allowMutations: true,
          scenarios: [
            {
              id: "production-mutation",
              title: "Production mutation must be blocked",
              dimension: "business-logic",
              steps: [
                {
                  name: "update",
                  path: "/resource",
                  method: "PATCH",
                },
              ],
              cleanup: [
                {
                  name: "cleanup",
                  path: "/resource",
                  method: "DELETE",
                },
              ],
            },
          ],
        },
      }),
      /production/,
    );
  } finally {
    instance.close();
    await once(instance, "close");
  }
});

test("attack audit carries a run id, authorization reference and cleanup failures", async () => {
  const { instance, origin } = await server((req, res) => {
    if (req.method === "GET") {
      res.statusCode = 200;
      res.end("{}");
      return;
    }
    res.statusCode = 500;
    res.end("cleanup failed");
  });
  process.env.REAPER_ATTACK_USER_A = "user-a-token";
  try {
    const result = await runAttack(origin, {
      attack: {
        allowedTargets: [origin],
        authorization: {
          acknowledged: true,
          reference: "SEC-1234",
          environment: "staging",
        },
        allowMutations: true,
        maxConsecutiveServerErrors: 1,
        identities: {
          userA: { tokenEnv: "REAPER_ATTACK_USER_A" },
        },
        scenarios: [
          {
            id: "audit",
            title: "Audit evidence",
            dimension: "ownership",
            steps: [
              {
                name: "read",
                path: "/foreign",
                actor: "userA",
                resource: "foreign:test-resource",
                expect: { deniedStatuses: [403, 404] },
              },
            ],
            cleanup: [
              {
                name: "cleanup",
                path: "/foreign",
                method: "DELETE",
                actor: "userA",
              },
            ],
          },
        ],
      },
    });
    assert.match(result.attack.runId, /^[0-9a-f-]{36}$/);
    assert.equal(result.attack.authorizationReference, "SEC-1234");
    assert.equal(result.attack.cleanupFailures, 1);
    assert.ok(
      result.attack.audit.some((event) => event.outcome === "cleanup-error"),
    );
    assert.ok(
      result.findings[0].evidence.includes(
        "Authorization reference: SEC-1234",
      ),
    );
  } finally {
    delete process.env.REAPER_ATTACK_USER_A;
    instance.close();
    await once(instance, "close");
  }
});


test("HTTP 500 is inconclusive, never a confirmed authorization bypass", async () => {
  const { instance, origin } = await server((_req, res) => {
    res.statusCode = 500;
    res.end("internal error");
  });
  process.env.REAPER_ATTACK_USER_A = "user-a-token";
  try {
    const result = await runAttack(origin, {
      attack: {
        allowedTargets: [origin],
        authorization: {
          acknowledged: true,
          reference: "SEC-500",
          environment: "staging",
        },
        identities: { userA: { tokenEnv: "REAPER_ATTACK_USER_A" } },
        scenarios: [{
          id: "inconclusive-server-error",
          title: "Server error is not a bypass",
          dimension: "ownership",
          steps: [{
            name: "foreign read",
            path: "/orders/foreign",
            actor: "userA",
            resource: "order:foreign:owner:userB",
            expect: { deniedStatuses: [403, 404] },
          }],
        }],
      },
    });
    assert.equal(result.findings.length, 0);
    assert.equal(result.attack.confirmed.length, 0);
    assert.ok(result.diagnostics.some((d) => /cannot confirm/.test(d.message)));
  } finally {
    delete process.env.REAPER_ATTACK_USER_A;
    instance.close();
    await once(instance, "close");
  }
});
