import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { once } from "node:events";
import { verify, validateConfig } from "../dist/index.js";

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
