import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import {
  buildEvidenceBundle,
  signEvidenceBundle,
  verifyEvidenceBundle,
  verifySignedEvidence,
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

test("evidence signatures verify against an explicit trusted Ed25519 key", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privatePem = privateKey
    .export({ type: "pkcs8", format: "pem" })
    .toString();
  const publicPem = publicKey
    .export({ type: "spki", format: "pem" })
    .toString();
  const report = {
    version: "0.2.0",
    root: "/app",
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
    coverage: { source: true, database: false, runtime: false },
  };
  const signed = signEvidenceBundle(buildEvidenceBundle(report), privatePem);
  const verified = verifySignedEvidence(signed, publicPem);
  assert.equal(verified.valid, true);
  assert.equal(verified.signatureValid, true);
  assert.equal(verified.keyFingerprint.length, 64);

  signed.bundle.payload.root = "/tampered";
  assert.equal(verifySignedEvidence(signed, publicPem).valid, false);
});
