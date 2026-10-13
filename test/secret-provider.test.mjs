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

test("oversized secrets are rejected and their provider lease is revoked", async () => {
  let requests = 0;
  let revocations = 0;
  const server = http.createServer((_req, res) => {
    requests++;
    res.end("unexpected request");
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const target = `http://127.0.0.1:${address.port}`;
  const provider = {
    get() {
      return "x".repeat(16_385);
    },
    revoke() {
      revocations++;
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
            reference: "oversized-secret-test",
            environment: "staging",
          },
          identities: { testUser: { tokenEnv: "REAPER_TEST_TOKEN" } },
          scenarios: [
            {
              id: "oversized-secret",
              title: "Reject an oversized leased secret",
              dimension: "session",
              steps: [{ name: "read", path: "/private", actor: "testUser" }],
            },
          ],
        },
      },
      { secretProvider: provider },
    );
    assert.equal(requests, 0);
    assert.equal(revocations, 1);
    assert.ok(JSON.stringify(result).includes("16 KiB limit"));
  } finally {
    server.closeAllConnections?.();
    server.close();
    await once(server, "close");
  }
});

test("captured session credentials are redacted from findings and graph output", async () => {
  const capturedSession = "SUPER_SECRET_CAPTURED_SESSION_726401";
  const server = http.createServer((req, res) => {
    if (req.url === "/login") {
      res.setHeader(
        "set-cookie",
        `session=${capturedSession}; HttpOnly; Secure`,
      );
      res.end("ok");
      return;
    }
    const authenticated = req.headers.cookie === `session=${capturedSession}`;
    res.statusCode = authenticated ? 200 : 401;
    res.end("ok");
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const target = `http://127.0.0.1:${address.port}`;
  try {
    const result = await runAttack(target, {
      attack: {
        allowedTargets: [target],
        authorization: {
          acknowledged: true,
          reference: "captured-session-redaction-test",
          environment: "staging",
        },
        identities: {
          testUser: { cookie: { name: "session", valueVar: "SESSION" } },
        },
        scenarios: [
          {
            id: "captured-session-redaction",
            title: "Redact captured session credential",
            dimension: "ownership",
            steps: [
              {
                name: "capture login session",
                path: "/login",
                captureCookies: { SESSION: "session" },
              },
              {
                name: "access known foreign resource",
                path: "/private",
                actor: "testUser",
                resource: "{{SESSION}}",
                expect: { deniedStatuses: [403], confirmStatuses: [200] },
              },
            ],
          },
        ],
      },
    });
    const artifacts = {
      result: JSON.stringify(result),
      json: report(result, "json"),
      sarif: report(result, "sarif"),
      audit: JSON.stringify(result.attack.audit),
      graph: JSON.stringify(result.graph),
    };
    assert.equal(result.findings.length, 1);
    const leakedArtifacts = Object.entries(artifacts)
      .filter(([, content]) => content.includes(capturedSession))
      .map(([name]) => name);
    const leakedFields = [];
    const findLeaks = (value, path = "result") => {
      if (typeof value === "string" && value.includes(capturedSession)) {
        leakedFields.push(path);
      } else if (Array.isArray(value)) {
        value.forEach((entry, index) => findLeaks(entry, `${path}[${index}]`));
      } else if (value && typeof value === "object") {
        for (const [key, entry] of Object.entries(value))
          findLeaks(entry, `${path}.${key}`);
      }
    };
    findLeaks(result);
    assert.deepEqual(leakedFields, []);
    assert.deepEqual(leakedArtifacts, []);
    assert.ok(
      Object.values(artifacts).some((content) =>
        content.includes("[REDACTED]"),
      ),
    );
  } finally {
    server.closeAllConnections?.();
    server.close();
    await once(server, "close");
  }
});
