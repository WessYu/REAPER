import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { once } from "node:events";
import { verify, validateConfig, discoverEndpoints } from "../dist/index.js";

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

test("verify confirms configured authorization failures on localhost", async () => {
  const { instance, origin } = await server((req, res) => {
    if (req.url === "/denied") {
      res.statusCode = 403;
      res.end("denied");
      return;
    }
    res.statusCode = 200;
    res.end("unexpected access");
  });
  try {
    const result = await verify(origin, {
      verify: {
        maxRequests: 4,
        concurrency: 2,
        timeoutMs: 2000,
        assertions: [
          {
            name: "ownership denied",
            path: "/denied",
            expectStatus: 403,
            dimension: "ownership",
          },
          {
            name: "cross tenant denied",
            path: "/allowed",
            expectStatus: 403,
            dimension: "tenant",
          },
        ],
      },
    });
    assert.equal(result.coverage.runtime, true);
    assert.equal(result.metrics.sinks, 2);
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].ruleId, "REAPER-VERIFY-001");
    assert.equal(result.findings[0].confidence, "CONFIRMED");
    assert.equal(result.findings[0].severity, "CRITICAL");
  } finally {
    instance.close();
    await once(instance, "close");
  }
});

test("verify never copies bearer token values into findings", async () => {
  const { instance, origin } = await server((req, res) => {
    assert.equal(req.headers.authorization, "Bearer synthetic-verify-token");
    res.statusCode = 200;
    res.end();
  });
  process.env.REAPER_VERIFY_TEST_TOKEN = "synthetic-verify-token";
  try {
    const result = await verify(origin, {
      verify: {
        assertions: [
          {
            name: "authenticated request must be denied",
            path: "/resource",
            expectStatus: 403,
            authEnv: "REAPER_VERIFY_TEST_TOKEN",
            dimension: "ownership",
          },
        ],
      },
    });
    assert.equal(result.findings.length, 1);
    assert.ok(!JSON.stringify(result).includes("synthetic-verify-token"));
  } finally {
    delete process.env.REAPER_VERIFY_TEST_TOKEN;
    instance.close();
    await once(instance, "close");
  }
});

test("remote verify is blocked unless exact origin is explicitly allowed", async () => {
  await assert.rejects(
    verify("https://example.com", {
      verify: {
        assertions: [
          { name: "blocked", path: "/", method: "HEAD", expectStatus: 403 },
        ],
      },
    }),
    /blocked/,
  );
});

test("verify config validation enforces budgets and safe methods", () => {
  assert.throws(
    () =>
      validateConfig({
        verify: {
          concurrency: 20,
          assertions: [{ name: "a", path: "/", expectStatus: 403 }],
        },
      }),
    /concurrency/,
  );
  assert.throws(
    () =>
      validateConfig({
        verify: {
          assertions: [
            { name: "a", path: "/", method: "POST", expectStatus: 403 },
          ],
        },
      }),
    /GET or HEAD/,
  );
});

test("verify supports global cancellation without continuing the request queue", async () => {
  let requests = 0;
  const { instance, origin } = await server((_req, res) => {
    requests++;
    setTimeout(() => {
      res.statusCode = 403;
      res.end();
    }, 200);
  });
  const controller = new AbortController();
  try {
    setTimeout(() => controller.abort(), 30);
    const result = await verify(
      origin,
      {
        verify: {
          concurrency: 1,
          rateLimitPerSecond: 20,
          timeoutMs: 1000,
          assertions: [
            { name: "first", path: "/one", expectStatus: 403 },
            { name: "second", path: "/two", expectStatus: 403 },
          ],
        },
      },
      { signal: controller.signal },
    );
    assert.ok(requests <= 1);
    assert.ok(
      result.diagnostics.some((item) => /cancelled/.test(item.message)),
    );
  } finally {
    instance.close();
    await once(instance, "close");
  }
});

test("verify config caps active request rate", () => {
  assert.throws(
    () =>
      validateConfig({
        verify: {
          rateLimitPerSecond: 21,
          assertions: [{ name: "a", path: "/", expectStatus: 403 }],
        },
      }),
    /rateLimitPerSecond/,
  );
});

test("OpenAPI discovery only returns GET and HEAD operations", async () => {
  const { instance, origin } = await server((req, res) => {
    res.setHeader("content-type", "application/json");
    if (req.url === "/openapi.json") {
      res.end(
        JSON.stringify({
          openapi: "3.1.0",
          paths: {
            "/orders": { get: {}, post: {} },
            "/health": { head: {} },
          },
        }),
      );
      return;
    }
    res.statusCode = 404;
    res.end();
  });
  try {
    const endpoints = await discoverEndpoints(origin, {
      verify: {
        discoverOpenApi: true,
        assertions: [],
      },
    });
    assert.deepEqual(endpoints, ["GET /orders", "HEAD /health"]);
  } finally {
    instance.close();
    await once(instance, "close");
  }
});

test("synthetic setup can capture credentials for assertions and teardown", async () => {
  let teardown = false;
  const { instance, origin } = await server((req, res) => {
    res.setHeader("content-type", "application/json");
    if (req.method === "POST" && req.url === "/test-users") {
      res.statusCode = 201;
      res.end(JSON.stringify({ token: "captured-synthetic-token", id: "u1" }));
      return;
    }
    if (req.method === "GET" && req.url === "/orders/u1") {
      assert.equal(
        req.headers.authorization,
        "Bearer captured-synthetic-token",
      );
      res.statusCode = 200;
      res.end("{}");
      return;
    }
    if (req.method === "DELETE" && req.url === "/test-users/u1") {
      teardown = true;
      res.statusCode = 204;
      res.end();
      return;
    }
    res.statusCode = 404;
    res.end("{}");
  });
  process.env.REAPER_SYNTH_EMAIL = "synthetic@example.test";
  try {
    const result = await verify(origin, {
      verify: {
        allowMutations: true,
        rateLimitPerSecond: 20,
        maxRequests: 6,
        setup: [
          {
            name: "create synthetic user",
            path: "/test-users",
            method: "POST",
            expectStatus: 201,
            body: { email: "$env:REAPER_SYNTH_EMAIL" },
            capture: { USER_TOKEN: "token", USER_ID: "id" },
          },
        ],
        assertions: [
          {
            name: "cross-user object must be denied",
            path: "/orders/{{USER_ID}}",
            expectStatus: 403,
            authVar: "USER_TOKEN",
            dimension: "ownership",
          },
        ],
        teardown: [
          {
            name: "delete synthetic user",
            path: "/test-users/{{USER_ID}}",
            method: "DELETE",
            expectStatus: 204,
          },
        ],
      },
    });
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].confidence, "CONFIRMED");
    assert.ok(!JSON.stringify(result).includes("captured-synthetic-token"));
    assert.equal(teardown, true);
  } finally {
    delete process.env.REAPER_SYNTH_EMAIL;
    instance.close();
    await once(instance, "close");
  }
});
