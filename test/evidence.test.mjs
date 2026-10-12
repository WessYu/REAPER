import { test } from "node:test";
import assert from "node:assert/strict";
import {
  buildEvidenceBundle,
  verifyEvidenceBundle,
} from "../dist/index.js";

test("evidence bundles are deterministic and tamper-evident", () => {
  const report = {
    version: "0.2.0",
    root: "/app",
    findings: [
      {
        id: "REAPER-AUTH-001:test",
        ruleId: "REAPER-AUTH-001",
        title: "Ownership unresolved",
        description: "",
        severity: "MEDIUM",
        confidence: "MEDIUM",
        category: "Authorization",
        file: "route.ts",
        line: 1,
        column: 1,
        evidence: ["bounded evidence"],
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
  const one = buildEvidenceBundle(report);
  const two = buildEvidenceBundle(report);
  assert.equal(one.digest.value, two.digest.value);
  assert.equal(one.digest.value.length, 64);
  assert.equal(verifyEvidenceBundle(one).valid, true);
  one.payload.findings[0].title = "tampered";
  assert.equal(verifyEvidenceBundle(one).valid, false);
});
