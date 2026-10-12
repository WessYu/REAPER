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
  if (!address || typeof address === "string") throw new Error("No port.");
  return { instance, origin: `http://127.0.0.1:${address.port}` };
}

test("active findings auto-correlate matching static authorization evidence", async () => {
  const { instance, origin } = await server((_req, res) => {
    res.statusCode = 200;
    res.end();
  });
  process.env.REAPER_CORRELATE_A = "a";
  process.env.REAPER_CORRELATE_B = "b";
  try {
    const sourceReport = {
      version: "0.2.0",
      root: "/app",
      findings: [
        {
          id: "REAPER-AUTH-001:static",
          ruleId: "REAPER-AUTH-001",
          title: "ownership missing",
          description: "",
          severity: "MEDIUM",
          confidence: "MEDIUM",
          category: "Authorization",
          file: "routes/orders.ts",
          line: 42,
          column: 3,
          route: "GET /api/orders/{{RESOURCE_ID}}",
          resource: "order",
          evidence: [],
          dataFlow: [],
          recommendation: "",
          fingerprint: "a".repeat(64),
          status: "new",
        },
      ],
      diagnostics: [],
      graph: { nodes: [], edges: [] },
      metrics: {
        files: 1,
        routes: 1,
        sinks: 1,
        durationMs: 1,
        memoryBytes: 1,
      },
      coverage: { source: true, database: false, runtime: false },
    };
    const result = await attack(
      origin,
      {
        scope: { authorized: true, environment: "local" },
        identities: {
          a: { authEnv: "REAPER_CORRELATE_A" },
          b: { authEnv: "REAPER_CORRELATE_B" },
        },
        scenarios: [
          {
            name: "foreign order",
            kind: "bola",
            attackerIdentity: "a",
            ownerIdentity: "b",
            resource: "order",
            attack: {
              name: "read foreign order",
              path: "/api/orders/{{RESOURCE_ID}}",
            },
          },
        ],
      },
      { sourceReport },
    );
    assert.equal(result.findings[0].file, "routes/orders.ts");
    assert.equal(result.findings[0].line, 42);
    assert.match(
      result.findings[0].evidence.join("\n"),
      /Correlated static finding/,
    );
    assert.ok(
      result.graph.edges.some(
        (edge) =>
          edge.relation === "correlates" &&
          edge.from === "finding:REAPER-AUTH-001:static",
      ),
    );
    assert.equal(result.attack.configHash.length, 64);
  } finally {
    delete process.env.REAPER_CORRELATE_A;
    delete process.env.REAPER_CORRELATE_B;
    instance.close();
    await once(instance, "close");
  }
});

test("expired active scopes are rejected before any request", async () => {
  await assert.rejects(
    attack("http://127.0.0.1:1", {
      scope: {
        authorized: true,
        environment: "local",
        expiresAt: "2020-01-01T00:00:00.000Z",
      },
      identities: { a: {} },
      scenarios: [
        {
          name: "expired",
          kind: "authorization",
          attackerIdentity: "a",
          attack: { name: "probe", path: "/" },
        },
      ],
    }),
    /expired/,
  );
});
