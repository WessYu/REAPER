import { test } from "node:test";
import assert from "node:assert/strict";
import { buildAttackPlan, buildIdentityMatrix } from "../dist/index.js";

test("attack planner converts ownership and tenant findings into reviewable candidates", () => {
  const report = {
    version: "0.2.0",
    root: "/app",
    findings: [
      {
        id: "REAPER-AUTH-001:a",
        ruleId: "REAPER-AUTH-001",
        title: "ownership",
        description: "",
        severity: "MEDIUM",
        confidence: "MEDIUM",
        category: "Authorization",
        file: "routes.ts",
        line: 1,
        column: 1,
        route: "GET /api/orders/:id",
        resource: "order",
        evidence: [],
        dataFlow: [],
        recommendation: "",
        fingerprint: "a".repeat(64),
        status: "new",
      },
      {
        id: "REAPER-TENANT-001:b",
        ruleId: "REAPER-TENANT-001",
        title: "tenant",
        description: "",
        severity: "HIGH",
        confidence: "MEDIUM",
        category: "Tenant Isolation",
        file: "routes.ts",
        line: 2,
        column: 1,
        route: "GET /api/invoices/[id]",
        resource: "invoice",
        evidence: [],
        dataFlow: [],
        recommendation: "",
        fingerprint: "b".repeat(64),
        status: "new",
      },
    ],
    diagnostics: [],
    graph: { nodes: [], edges: [] },
    metrics: {
      files: 1,
      routes: 2,
      sinks: 2,
      durationMs: 1,
      memoryBytes: 1,
    },
    coverage: { source: true, database: false, runtime: false },
  };
  const plan = buildAttackPlan(report);
  assert.equal(plan.candidates.length, 2);
  assert.equal(plan.candidates[0].pathTemplate, "/api/orders/{{RESOURCE_ID}}");
  assert.equal(plan.candidates[1].pathTemplate, "/api/invoices/{{RESOURCE_ID}}");
  assert.ok(plan.candidates.every((item) => item.prerequisites.length > 0));
});

test("identity matrix distinguishes same-role ownership from cross-tenant pairs", () => {
  const entries = buildIdentityMatrix({
    scope: { authorized: true, environment: "local" },
    identities: {
      userA: { role: "user", tenant: "a" },
      userB: { role: "user", tenant: "b" },
      admin: { role: "admin", tenant: "a" },
    },
    scenarios: [],
  });
  const pair = entries.find(
    (entry) => entry.attacker === "userA" && entry.owner === "userB",
  );
  assert.deepEqual(pair.dimensions, ["ownership", "tenant"]);
  assert.equal(
    entries.some(
      (entry) => entry.attacker === "userA" && entry.owner === "admin",
    ),
    false,
  );
});
