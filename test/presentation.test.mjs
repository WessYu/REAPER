import { test } from "node:test";
import assert from "node:assert/strict";
import {
  renderGraph,
  renderExplanation,
  renderDashboard,
  scan,
} from "../dist/index.js";

test("graph renderer produces deterministic JSON and DOT", () => {
  const graph = {
    nodes: [
      { id: "resource:orders", kind: "resource", label: "orders" },
      { id: "route:GET /orders", kind: "route", label: "GET /orders" },
    ],
    edges: [
      {
        from: "route:GET /orders",
        to: "resource:orders",
        relation: "accesses",
      },
    ],
  };
  const dot = renderGraph(graph, "dot");
  assert.match(dot, /^digraph REAPER/);
  assert.match(dot, /GET \/orders/);
  assert.deepEqual(JSON.parse(renderGraph(graph, "json")), graph);
});

test("finding explanation keeps evidence and remediation visible", () => {
  const finding = {
    id: "REAPER-AUTH-001:abc",
    ruleId: "REAPER-AUTH-001",
    title: "Ownership constraint not established",
    description: "test",
    severity: "HIGH",
    confidence: "MEDIUM",
    category: "Authorization",
    file: "route.ts",
    line: 10,
    column: 3,
    route: "GET /orders/:id",
    resource: "order",
    evidence: ["Ownership relationship: userId"],
    dataFlow: [
      {
        file: "route.ts",
        line: 10,
        column: 20,
        kind: "source",
        label: "req.params.id",
      },
    ],
    recommendation: "Scope the query.",
    fingerprint: "a".repeat(64),
    status: "new",
  };
  const output = renderExplanation(finding, "terminal");
  assert.match(output, /WHY FLAGGED/);
  assert.match(output, /DATA FLOW/);
  assert.match(output, /Scope the query/);
});

test("dashboard renderer creates a self-contained review artifact", async () => {
  const result = await scan({ root: "test/fixtures/vulnerable" });
  const html = renderDashboard(result);
  assert.match(html, /<!doctype html>/);
  assert.match(html, /Security score/);
  assert.match(html, /REAPER-SQL-001/);
});

test("dashboard renders active-security provenance without secret material", () => {
  const result = {
    version: "0.2.0",
    root: "http://127.0.0.1",
    findings: [],
    diagnostics: [],
    graph: { nodes: [], edges: [] },
    metrics: {
      files: 0,
      routes: 1,
      sinks: 1,
      durationMs: 5,
      memoryBytes: 1,
    },
    coverage: { source: false, database: false, runtime: true },
    attack: {
      target: "http://127.0.0.1",
      environment: "local",
      authorizationId: "ENG-42",
      configHash: "a".repeat(64),
      startedAt: "2026-10-12T00:00:00.000Z",
      requestCount: 1,
      serverErrors: 0,
      auditHash: "b".repeat(64),
      scenarios: [{ name: "foreign order", kind: "bola", status: "passed" }],
      audit: [
        {
          sequence: 1,
          scenario: "foreign order",
          step: "probe",
          identity: "userA",
          method: "GET",
          path: "/api/orders/{{RESOURCE_ID}}",
          status: 403,
          durationMs: 4,
          phase: "attack",
          previousHash: "",
          hash: "b".repeat(64),
        },
      ],
    },
  };
  const html = renderDashboard(result);
  assert.match(html, /Active security run/);
  assert.match(html, /ENG-42/);
  assert.match(html, /foreign order/);
  assert.doesNotMatch(html, /Bearer|token-/);
});
