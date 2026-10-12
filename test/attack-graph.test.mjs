import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { once } from "node:events";
import { attack } from "../dist/index.js";

test("active attack merges static route graph and emits trace IDs", async () => {
  const traceIds = [];
  const server = http.createServer((req, res) => {
    const trace = req.headers["x-reaper-trace-id"];
    assert.equal(typeof trace, "string");
    traceIds.push(trace);
    if (req.method === "POST" && req.url === "/api/orders") {
      res.setHeader("content-type", "application/json");
      res.statusCode = 201;
      res.end(JSON.stringify({ id: "order-b" }));
      return;
    }
    if (req.method === "GET" && req.url === "/api/orders/order-b") {
      res.statusCode = 200;
      res.end();
      return;
    }
    res.statusCode = 404;
    res.end();
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("No port.");
  const origin = `http://127.0.0.1:${address.port}`;

  const sourceReport = {
    version: "0.2.0",
    root: "/app",
    findings: [
      {
        id: "REAPER-AUTH-001:static",
        ruleId: "REAPER-AUTH-001",
        title: "Ownership constraint unresolved",
        description: "",
        severity: "MEDIUM",
        confidence: "MEDIUM",
        category: "Authorization",
        file: "routes/orders.ts",
        line: 42,
        column: 1,
        route: "GET /api/orders/:id",
        resource: "order",
        evidence: [],
        dataFlow: [],
        recommendation: "",
        fingerprint: "a".repeat(64),
        status: "new",
      },
    ],
    diagnostics: [],
    graph: {
      nodes: [
        {
          id: "route:GET /api/orders/:id",
          kind: "route",
          label: "GET /api/orders/:id",
        },
        { id: "query:orders", kind: "query", label: "Order.findUnique" },
        { id: "resource:order", kind: "resource", label: "order" },
      ],
      edges: [
        {
          from: "route:GET /api/orders/:id",
          to: "query:orders",
          relation: "calls",
        },
        { from: "query:orders", to: "resource:order", relation: "accesses" },
      ],
    },
    metrics: {
      files: 7,
      routes: 1,
      sinks: 1,
      durationMs: 10,
      memoryBytes: 1,
    },
    coverage: { source: true, database: false, runtime: false },
  };

  try {
    const result = await attack(
      origin,
      {
        scope: { authorized: true, environment: "local" },
        allowMutations: true,
        identities: { userA: {}, userB: {} },
        scenarios: [
          {
            name: "foreign order",
            kind: "bola",
            attackerIdentity: "userA",
            ownerIdentity: "userB",
            resource: "order",
            setup: [
              {
                name: "create owner order",
                path: "/api/orders",
                method: "POST",
                identity: "userB",
                expectStatus: 201,
                capture: { RESOURCE_ID: "id" },
              },
            ],
            attack: {
              name: "read foreign order",
              path: "/api/orders/{{RESOURCE_ID}}",
              method: "GET",
            },
          },
        ],
      },
      { sourceReport },
    );

    assert.equal(result.coverage.source, true);
    assert.equal(result.metrics.files, 7);
    assert.equal(result.findings[0].file, "routes/orders.ts");
    assert.equal(result.attack.audit.length, 2);
    assert.equal(result.attack.audit[0].traceId.length, 36);
    assert.equal(result.attack.audit[1].traceId.length, 36);
    assert.deepEqual(
      traceIds,
      result.attack.audit.map((event) => event.traceId),
    );
    assert.ok(
      result.graph.edges.some(
        (edge) =>
          edge.from === "request:foreign order" &&
          edge.to === "route:GET /api/orders/:id" &&
          edge.relation === "correlates",
      ),
    );
    assert.ok(
      result.graph.edges.some(
        (edge) =>
          edge.from === "route:GET /api/orders/:id" &&
          edge.to === "query:orders",
      ),
    );
  } finally {
    server.close();
    await once(server, "close");
  }
});
