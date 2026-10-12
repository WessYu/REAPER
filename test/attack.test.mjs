import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { once } from "node:events";
import { attack } from "../dist/index.js";

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

function config(overrides = {}) {
  return {
    scope: {
      authorized: true,
      environment: "local",
      pathPrefixes: ["/api/"],
    },
    allowMutations: true,
    maxRequests: 10,
    rateLimitPerSecond: 20,
    identities: {
      userA: { authEnv: "REAPER_ATTACK_A", role: "user", tenant: "a" },
      userB: { authEnv: "REAPER_ATTACK_B", role: "user", tenant: "b" },
    },
    scenarios: [
      {
        name: "cross-user order",
        kind: "bola",
        attackerIdentity: "userA",
        ownerIdentity: "userB",
        resource: "order",
        setup: [
          {
            name: "create order",
            path: "/api/orders",
            method: "POST",
            identity: "userB",
            body: { label: "synthetic" },
            expectStatus: 201,
            capture: { RESOURCE_ID: "id" },
          },
        ],
        attack: {
          name: "read foreign order",
          path: "/api/orders/{{RESOURCE_ID}}",
          method: "GET",
        },
        cleanup: [
          {
            name: "cleanup order",
            path: "/api/orders/{{RESOURCE_ID}}",
            method: "DELETE",
            identity: "userB",
            expectStatus: 204,
          },
        ],
        denyStatuses: [401, 403, 404],
      },
    ],
    ...overrides,
  };
}

test("active engine confirms BOLA while redacting tokens and cleaning state", async () => {
  let deleted = false;
  const { instance, origin } = await server((req, res) => {
    res.setHeader("content-type", "application/json");
    if (req.method === "POST" && req.url === "/api/orders") {
      assert.equal(req.headers.authorization, "Bearer token-b");
      res.statusCode = 201;
      res.end(JSON.stringify({ id: "order-b" }));
      return;
    }
    if (req.method === "GET" && req.url === "/api/orders/order-b") {
      assert.equal(req.headers.authorization, "Bearer token-a");
      res.statusCode = 200;
      res.end(JSON.stringify({ id: "order-b", secret: "not-captured" }));
      return;
    }
    if (req.method === "DELETE" && req.url === "/api/orders/order-b") {
      assert.equal(req.headers.authorization, "Bearer token-b");
      deleted = true;
      res.statusCode = 204;
      res.end();
      return;
    }
    res.statusCode = 404;
    res.end("{}");
  });
  process.env.REAPER_ATTACK_A = "token-a";
  process.env.REAPER_ATTACK_B = "token-b";
  try {
    const result = await attack(origin, config());
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].ruleId, "REAPER-ATTACK-001");
    assert.equal(result.findings[0].confidence, "CONFIRMED");
    assert.equal(result.attack.scenarios[0].status, "confirmed");
    assert.equal(result.attack.audit.length, 3);
    assert.equal(result.attack.audit[0].previousHash, "");
    assert.equal(result.attack.audit[0].hash.length, 64);
    assert.equal(
      result.attack.audit[1].previousHash,
      result.attack.audit[0].hash,
    );
    assert.equal(result.attack.auditHash, result.attack.audit.at(-1).hash);
    assert.equal(deleted, true);
    assert.ok(!JSON.stringify(result).includes("token-a"));
    assert.ok(!JSON.stringify(result).includes("token-b"));
    assert.ok(!JSON.stringify(result).includes("not-captured"));
  } finally {
    delete process.env.REAPER_ATTACK_A;
    delete process.env.REAPER_ATTACK_B;
    instance.close();
    await once(instance, "close");
  }
});

test("active engine records a passed denial without inventing a finding", async () => {
  const { instance, origin } = await server((req, res) => {
    if (req.method === "POST") {
      res.setHeader("content-type", "application/json");
      res.statusCode = 201;
      res.end(JSON.stringify({ id: "order-b" }));
      return;
    }
    if (req.method === "GET") {
      res.statusCode = 403;
      res.end();
      return;
    }
    if (req.method === "DELETE") {
      res.statusCode = 204;
      res.end();
      return;
    }
    res.statusCode = 404;
    res.end();
  });
  process.env.REAPER_ATTACK_A = "token-a";
  process.env.REAPER_ATTACK_B = "token-b";
  try {
    const result = await attack(origin, config());
    assert.equal(result.findings.length, 0);
    assert.equal(result.attack.scenarios[0].status, "passed");
  } finally {
    delete process.env.REAPER_ATTACK_A;
    delete process.env.REAPER_ATTACK_B;
    instance.close();
    await once(instance, "close");
  }
});

test("active engine enforces path scope and remote target authorization", async () => {
  await assert.rejects(
    attack(
      "https://example.com",
      config({ allowMutations: false, scenarios: [] }),
    ),
    /blocked/,
  );
  const { instance, origin } = await server((_req, res) => {
    res.statusCode = 200;
    res.end();
  });
  process.env.REAPER_ATTACK_A = "token-a";
  process.env.REAPER_ATTACK_B = "token-b";
  try {
    const scoped = config({
      allowMutations: false,
      scenarios: [
        {
          name: "outside scope",
          kind: "authorization",
          attackerIdentity: "userA",
          attack: { name: "probe", path: "/admin", method: "GET" },
        },
      ],
    });
    const result = await attack(origin, scoped);
    assert.equal(result.findings.length, 0);
    assert.ok(
      result.diagnostics.some((item) =>
        /outside configured scope/.test(item.message),
      ),
    );
  } finally {
    delete process.env.REAPER_ATTACK_A;
    delete process.env.REAPER_ATTACK_B;
    instance.close();
    await once(instance, "close");
  }
});
