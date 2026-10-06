import { test } from "node:test";
import assert from "node:assert/strict";
import { calculateScore, renderScore } from "../dist/index.js";

const base = () => ({
  version: "0.1.0",
  root: "/fixture",
  findings: [],
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
});

const makeFinding = (overrides = {}) => ({
  id: "REAPER-TEST:1",
  ruleId: "REAPER-AUTH-001",
  title: "test",
  description: "test",
  severity: "HIGH",
  confidence: "HIGH",
  category: "Authorization",
  file: "a.ts",
  line: 1,
  column: 1,
  evidence: [],
  dataFlow: [],
  recommendation: "test",
  fingerprint: "a".repeat(64),
  status: "new",
  ...overrides,
});

test("score remains 100 with no findings and high findings cannot be averaged away", () => {
  assert.equal(calculateScore(base()).overall, 100);
  const result = base();
  result.findings.push(makeFinding());
  const score = calculateScore(result);
  assert.equal(score.overall, 70);
  assert.ok(score.categories.Authorization < 100);
});

test("confirmed critical findings strongly cap the score while suppressions do not count", () => {
  const result = base();
  result.findings.push(
    makeFinding({
      severity: "CRITICAL",
      confidence: "CONFIRMED",
      category: "Privileges",
    }),
  );
  assert.equal(calculateScore(result).overall, 20);
  result.findings[0].status = "suppressed";
  assert.equal(calculateScore(result).overall, 100);
});

test("score rendering is explicit about limitations", () => {
  const output = renderScore(calculateScore(base()), "terminal");
  assert.match(output, /triage aid/);
  assert.throws(() => renderScore(calculateScore(base()), "sarif"));
});
