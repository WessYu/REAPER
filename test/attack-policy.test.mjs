import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { once } from "node:events";
import { attack, validateAttackConfig } from "../dist/index.js";

async function server(handler) {
  const instance = http.createServer(handler);
  instance.listen(0, "127.0.0.1");
  await once(instance, "listening");
  const address = instance.address();
  if (!address || typeof address === "string") throw new Error("No test port.");
  return { instance, origin: `http://127.0.0.1:${address.port}` };
}

test("CORS active scenario confirms an unexpected credentialed origin response", async () => {
  const { instance, origin } = await server((req, res) => {
    assert.equal(req.headers.origin, "https://attacker.example.test");
    res.setHeader(
      "access-control-allow-origin",
      "https://attacker.example.test",
    );
    res.setHeader("access-control-allow-credentials", "true");
    res.statusCode = 200;
    res.end();
  });
  try {
    const result = await attack(origin, {
      scope: { authorized: true, environment: "local" },
      identities: { anonymous: {} },
      scenarios: [
        {
          name: "untrusted origin must not receive credentialed CORS",
          kind: "cors",
          attackerIdentity: "anonymous",
          attack: {
            name: "cross-origin probe",
            path: "/api/account",
            headers: { origin: "https://attacker.example.test" },
          },
          expect: {
            statuses: [200],
            absentHeaders: ["access-control-allow-credentials"],
          },
        },
      ],
    });
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].ruleId, "REAPER-ATTACK-006");
    assert.equal(result.findings[0].confidence, "CONFIRMED");
    assert.match(
      result.findings[0].evidence.join("\n"),
      /access-control-allow-credentials/,
    );
  } finally {
    instance.close();
    await once(instance, "close");
  }
});

test("session scenario supports cookie identities without copying cookies into evidence", async () => {
  const { instance, origin } = await server((req, res) => {
    assert.equal(req.headers.cookie, "sid=synthetic-secret");
    res.statusCode = 200;
    res.end();
  });
  process.env.REAPER_SESSION_COOKIE = "sid=synthetic-secret";
  try {
    const result = await attack(origin, {
      scope: { authorized: true, environment: "local" },
      identities: {
        staleSession: { cookieEnv: "REAPER_SESSION_COOKIE" },
      },
      scenarios: [
        {
          name: "revoked session must be denied",
          kind: "session",
          attackerIdentity: "staleSession",
          attack: { name: "reuse session", path: "/api/me" },
          expect: { statuses: [401, 403] },
        },
      ],
    });
    assert.equal(result.findings[0].ruleId, "REAPER-ATTACK-005");
    assert.ok(!JSON.stringify(result).includes("synthetic-secret"));
  } finally {
    delete process.env.REAPER_SESSION_COOKIE;
    instance.close();
    await once(instance, "close");
  }
});

test("active config blocks direct authorization/cookie header injection", () => {
  assert.throws(
    () =>
      validateAttackConfig({
        scope: { authorized: true, environment: "local" },
        identities: { a: {} },
        scenarios: [
          {
            name: "bad header",
            kind: "authorization",
            attackerIdentity: "a",
            attack: {
              name: "probe",
              path: "/",
              headers: { authorization: "Bearer literal" },
            },
          },
        ],
      }),
    /blocked header/,
  );
});
