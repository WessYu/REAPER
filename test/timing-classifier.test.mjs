import test from "node:test";
import assert from "node:assert/strict";
import {
  classifyTimingObservations,
  contentEffectDiagnostic,
  timingDriftDiagnostic,
  TIMING_REASON_SCHEMA_VERSION,
} from "../dist/index.js";

function observations({ delay = 0, hash = "same-body" } = {}) {
  const samples = [];
  let order = 0;
  for (const role of ["baseline", "negative", "positive"]) {
    for (let i = 0; i < 5; i++) {
      samples.push({
        role,
        order: order++,
        outcome: "ok",
        elapsedMs: 40 + (role === "positive" ? delay : 0) + (i % 3),
        httpStatus: 200,
        bodyBytes: 32,
        normalizedBodyHash: hash,
        markerMatched: true,
      });
    }
  }
  return samples;
}

test("pure timing classifier yields versioned reason codes", () => {
  const result = classifyTimingObservations(observations({ delay: 100 }), 100);
  assert.equal(result.reasonSchemaVersion, TIMING_REASON_SCHEMA_VERSION);
  assert.equal(result.reasonCode, "DIFFERENTIAL_ABOVE_THRESHOLD");
  assert.equal(result.confirmed, true);
  assert.equal(result.thresholdMs, 80);
});

test("classification is invariant under changes to sample collection order", () => {
  const initial = observations({ delay: 100 });
  const original = classifyTimingObservations(initial, 100);
  const reversed = classifyTimingObservations(
    initial
      .map((sample, index) => ({
        ...sample,
        order: initial.length - index,
      }))
      .reverse(),
    100,
  );
  assert.deepEqual(original, reversed);
  assert.notEqual(timingDriftDiagnostic(initial), undefined);
});

test("unchanged response content never blocks true blind timing evidence", () => {
  const samples = observations({ delay: 100 });
  assert.equal(contentEffectDiagnostic(samples), "CONTENT_EFFECT_UNOBSERVED");
  assert.equal(classifyTimingObservations(samples, 100).confirmed, true);
});

test("unhealthy HTTP metadata fails closed and cannot create a finding", () => {
  const samples = observations({ delay: 100 });
  samples[5] = { ...samples[5], outcome: "http-error", httpStatus: 401 };
  const decision = classifyTimingObservations(samples, 100);
  assert.equal(decision.reasonCode, "INCOMPLETE_OR_UNHEALTHY_CONTROLS");
  assert.equal(decision.confidence, "INCONCLUSIVE");
});

test("invalid successful HTTP metadata cannot be treated as valid latency", () => {
  const samples = observations({ delay: 100 });
  samples[10] = { ...samples[10], httpStatus: 403 };
  assert.throws(
    () => classifyTimingObservations(samples, 100),
    /metadata is inconsistent/,
  );
  assert.throws(
    () => classifyTimingObservations(samples, 0),
    /must be positive/,
  );
});

test("content effect diagnostics are explicitly separate from classification", () => {
  const samples = observations({ delay: 0 });
  const finding = classifyTimingObservations(samples, 100);
  assert.equal(finding.confirmed, false);
  assert.equal(finding.reasonCode, "DIFFERENTIAL_BELOW_THRESHOLD");
  samples[5].normalizedBodyHash = "different-body";
  assert.equal(contentEffectDiagnostic(samples), "CONTENT_EFFECT_OBSERVED");
  delete samples[5].normalizedBodyHash;
  assert.equal(contentEffectDiagnostic(samples), "CONTENT_NOT_MEASURED");
});
