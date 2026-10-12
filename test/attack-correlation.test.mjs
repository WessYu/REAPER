import { test } from "node:test";
import assert from "node:assert/strict";
import { correlateAttackSource, normalizeAttackRoute } from "../dist/index.js";

const baseResult = (root) => ({
  version: "0.2.0",
  root,
  findings: [],
  diagnostics: [],
  graph: { nodes: [], edges: [] },
  metrics: {
    files: 0,
    routes: 0,
    sinks: 0,
    durationMs: 0,
    memoryBytes: 0,
  },
  coverage: { source: false, database: false, runtime: true },
});

test("attack/source correlation normalizes route parameters and carries data resources", () => {
  const attack = baseResult("https://preview.example.test");
  attack.findings.push({
    id: "REAPER-ATTACK-001:abc",
    ruleId: "REAPER-ATTACK-001",
    title: "Configured authorization boundary was bypassed",
    description: "test",
    severity: "HIGH",
    confidence: "CONFIRMED",
    category: "Offensive Validation",
    file: "runtime:orders",
    line: 1,
    column: 1,
    route: "GET /orders/{{RESOURCE_ID}}",
    resource: "order B",
    evidence: [],
    dataFlow: [],
    recommendation: "fix",
    fingerprint: "a".repeat(64),
    status: "new",
  });

  const source = baseResult("application");
  source.coverage = { source: true, database: true, runtime: false };
  source.graph.nodes.push(
    { id: "route:GET /orders/:id", kind: "route", label: "GET /orders/:id" },
    { id: "query:orders", kind: "query", label: "prisma.order.findUnique" },
    { id: "resource:order", kind: "resource", label: "order" },
  );
  source.graph.edges.push(
    {
      from: "route:GET /orders/:id",
      to: "query:orders",
      relation: "calls",
    },
    {
      from: "query:orders",
      to: "resource:order",
      relation: "accesses",
    },
  );
  source.findings.push({
    id: "REAPER-AUTH-001:def",
    ruleId: "REAPER-AUTH-001",
    title: "Ownership review",
    description: "test",
    severity: "MEDIUM",
    confidence: "MEDIUM",
    category: "Authorization",
    file: "routes.ts",
    line: 10,
    column: 1,
    route: "GET /orders/:id",
    evidence: [],
    dataFlow: [],
    recommendation: "fix",
    fingerprint: "b".repeat(64),
    status: "new",
  });

  const result = correlateAttackSource(attack, source);
  assert.equal(result.coverage.source, true);
  assert.equal(result.coverage.database, true);
  assert.ok(
    result.findings[0].evidence.includes(
      "Correlated source route: GET /orders/:id",
    ),
  );
  assert.ok(
    result.findings[0].evidence.includes(
      "Correlated source data resource: order",
    ),
  );
  assert.ok(
    result.findings[0].evidence.includes(
      "Correlated static/catalog finding: REAPER-AUTH-001",
    ),
  );
  assert.ok(result.graph.nodes.some((node) => node.id === "resource:order"));
});

test("attack route normalization treats common parameter syntaxes equivalently", () => {
  assert.equal(
    normalizeAttackRoute("GET /orders/{{RESOURCE_ID}}"),
    "GET /orders/*",
  );
  assert.equal(normalizeAttackRoute("GET /orders/:id"), "GET /orders/*");
  assert.equal(normalizeAttackRoute("GET /orders/{id}"), "GET /orders/*");
});
