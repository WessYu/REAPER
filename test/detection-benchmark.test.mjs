import test from "node:test";
import assert from "node:assert/strict";
import {
  confusionMetrics,
  benchmarkSeededFixtures,
} from "../scripts/benchmark-fixtures.mjs";

test("confusion metrics track both false positives and false negatives", () => {
  const stats = confusionMetrics([
    { expected: true, observed: true },
    { expected: true, observed: false },
    { expected: false, observed: true },
    { expected: false, observed: false },
  ]);
  assert.deepEqual(stats, {
    tp: 1,
    fp: 1,
    fn: 1,
    tn: 1,
    precision: 0.5,
    recall: 0.5,
    specificity: 0.5,
    sampleCount: 4,
  });
});

test("planted AppSec fixture families are detected without secure fixture noise", async () => {
  const benchmark = await benchmarkSeededFixtures();
  assert.equal(benchmark.metrics.sampleCount, 6);
  assert.equal(benchmark.metrics.tp, 3);
  assert.equal(benchmark.metrics.fn, 0);
  assert.equal(benchmark.metrics.fp, 0);
  assert.equal(benchmark.metrics.tn, 3);
  assert.match(benchmark.disclaimer, /cannot establish real-world/);
});
