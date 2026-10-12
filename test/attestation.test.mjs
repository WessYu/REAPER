import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import {
  attestReport,
  canonicalReport,
  reportDigest,
  validateAttestation,
  verifyReportAttestation,
} from "../dist/index.js";

function result() {
  return {
    version: "0.2.0",
    root: "application",
    findings: [
      {
        id: "REAPER-TEST-001:abc",
        ruleId: "REAPER-TEST-001",
        title: "Synthetic",
        description: "Synthetic test finding.",
        severity: "HIGH",
        confidence: "HIGH",
        category: "Authorization",
        file: "routes.ts",
        line: 1,
        column: 1,
        evidence: ["synthetic"],
        dataFlow: [],
        recommendation: "Synthetic.",
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
}

test("report attestation signs and verifies canonical report content", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" });
  const publicPem = publicKey.export({ type: "spki", format: "pem" });
  const report = result();
  const attestation = attestReport(
    report,
    privatePem,
    "2026-10-12T22:00:00.000Z",
  );

  assert.equal(attestation.format, "reaper-attestation-v1");
  assert.equal(attestation.digest.value, reportDigest(report));
  assert.equal(verifyReportAttestation(report, attestation, publicPem), true);
  assert.doesNotThrow(() => validateAttestation(attestation));
  assert.ok(!JSON.stringify(attestation).includes("PRIVATE KEY"));
});

test("report attestation detects report tampering", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" });
  const publicPem = publicKey.export({ type: "spki", format: "pem" });
  const report = result();
  const attestation = attestReport(report, privatePem);
  report.findings[0].title = "Tampered";
  assert.equal(verifyReportAttestation(report, attestation, publicPem), false);
});

test("canonical report serialization ignores object insertion order", () => {
  const left = result();
  const right = JSON.parse(JSON.stringify(left));
  right.metrics = {
    memoryBytes: 1,
    durationMs: 1,
    sinks: 1,
    routes: 1,
    files: 1,
  };
  assert.equal(canonicalReport(left), canonicalReport(right));
});

test("report attestation rejects non-Ed25519 signing keys", () => {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const pem = privateKey.export({ type: "pkcs8", format: "pem" });
  assert.throws(() => attestReport(result(), pem), /Ed25519/);
});
