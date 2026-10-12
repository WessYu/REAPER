import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { verifyAttackAudit } from "../dist/index.js";

function event(base) {
  return {
    ...base,
    hash: createHash("sha256")
      .update(base.previousHash)
      .update(JSON.stringify(base))
      .digest("hex"),
  };
}

test("audit verifier accepts intact chains and detects tampering", () => {
  const one = event({
    sequence: 1,
    scenario: "foreign order",
    step: "probe",
    identity: "userA",
    method: "GET",
    path: "/api/orders/{{RESOURCE_ID}}",
    status: 403,
    durationMs: 5,
    phase: "attack",
    previousHash: "",
  });
  const two = event({
    sequence: 2,
    scenario: "foreign order",
    step: "cleanup",
    identity: "userB",
    method: "DELETE",
    path: "/api/orders/{{RESOURCE_ID}}",
    status: 204,
    durationMs: 4,
    phase: "cleanup",
    previousHash: one.hash,
  });
  const report = {
    version: "0.2.0",
    root: "runtime",
    findings: [],
    diagnostics: [],
    graph: { nodes: [], edges: [] },
    metrics: {
      files: 0,
      routes: 1,
      sinks: 2,
      durationMs: 10,
      memoryBytes: 1,
    },
    coverage: { source: false, database: false, runtime: true },
    attack: {
      target: "http://127.0.0.1",
      environment: "local",
      configHash: "c".repeat(64),
      startedAt: "2026-10-12T00:00:00.000Z",
      requestCount: 2,
      mutationCount: 1,
      serverErrors: 0,
      auditHash: two.hash,
      scenarios: [{ name: "foreign order", kind: "bola", status: "passed" }],
      audit: [one, two],
    },
  };
  assert.equal(verifyAttackAudit(report).valid, true);
  report.attack.audit[0].status = 200;
  const altered = verifyAttackAudit(report);
  assert.equal(altered.valid, false);
  assert.ok(altered.errors.some((message) => /hash/.test(message)));
});
