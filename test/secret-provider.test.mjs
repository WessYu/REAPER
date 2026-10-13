import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { once } from "node:events";
import { InMemorySecretProvider, report, runAttack } from "../dist/index.js";

const sentinel = "SUPER_SECRET_REAPER_TEST_927461";

test("secret provider leases stay out of result/report/audit and are revoked", async () => {
  let observedCredential = false;
  const server = http.createServer((req, res) => {
    observedCredential = req.headers.authorization === `Bearer ${sentinel}`;
    res.statusCode = observedCredential ? 200 : 401;
    res.end("ok");
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const target = `http://127.0.0.1:${address.port}`;
  const provider = new InMemorySecretProvider({ REAPER_TEST_TOKEN: sentinel });
  try {
    const result = await runAttack(
      target,
      {
        attack: {
          allowedTargets: [target],
          authorization: {
            acknowledged: true,
            reference: "secret-provider-test",
            environment: "staging",
          },
          identities: {
            testUser: { tokenEnv: "REAPER_TEST_TOKEN" },
          },
          scenarios: [
            {
              id: "lease-token",
              title: "Use a short-lived secret reference",
              dimension: "session",
              steps: [
                {
                  name: "authenticated read",
                  path: "/private",
                  actor: "testUser",
                  expect: { allowedStatuses: [200] },
                },
              ],
            },
          ],
        },
      },
      { secretProvider: provider },
    );

    const artifacts = [
      JSON.stringify(result),
      report(result, "json"),
      report(result, "sarif"),
      JSON.stringify(result.attack.audit),
      JSON.stringify(result.diagnostics),
    ].join("\n");
    assert.equal(observedCredential, true);
    assert.equal(artifacts.includes(sentinel), false);
    assert.equal(
      await provider.get("REAPER_TEST_TOKEN", {
        runId: result.attack.runId,
        targetOrigin: target,
        purpose: "post-run check",
      }),
      undefined,
    );
  } finally {
    server.closeAllConnections?.();
    server.close();
    await once(server, "close");
  }
});

test("secret provider failures produce sanitized diagnostics", async () => {
  const server = http.createServer((_req, res) => {
    res.statusCode = 200;
    res.end("ok");
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const target = `http://127.0.0.1:${address.port}`;
  const provider = {
    get() {
      throw new Error(`provider failure leaked ${sentinel}`);
    },
  };
  try {
    const result = await runAttack(
      target,
      {
        attack: {
          allowedTargets: [target],
          authorization: {
            acknowledged: true,
            reference: "secret-provider-error-test",
            environment: "staging",
          },
          identities: { testUser: { tokenEnv: "REAPER_TEST_TOKEN" } },
          scenarios: [
            {
              id: "provider-error",
              title: "Do not expose provider errors",
              dimension: "session",
              steps: [{ name: "read", path: "/private", actor: "testUser" }],
            },
          ],
        },
      },
      { secretProvider: provider },
    );
    const artifacts = JSON.stringify(result);
    assert.ok(artifacts.includes("Secret provider failed"));
    assert.equal(artifacts.includes(sentinel), false);
  } finally {
    server.closeAllConnections?.();
    server.close();
    await once(server, "close");
  }
});
