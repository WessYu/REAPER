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
