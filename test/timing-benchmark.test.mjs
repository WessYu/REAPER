import test from "node:test";
import assert from "node:assert/strict";
import {
  virtualTimingTrial,
  benchmarkTimingScenario,
} from "../scripts/benchmark-timing.mjs";

const config = {
  trials: 50,
  seed: 1742,
  samples: 5,
  expectedDelayMs: 500,
  sigma: 20,
  jitterRegime: "abs",
  distribution: "gaussian",
};

test("seeded benchmark is bit-for-bit reproducible", () => {
  assert.deepEqual(
    benchmarkTimingScenario(config),
    benchmarkTimingScenario(config),
  );
});

test("zero jitter separates the two ground-truth populations", () => {
  const result = benchmarkTimingScenario({
    ...config,
    sigma: 0,
    distribution: "uniform",
  });
  assert.equal(result.counts.falsePositives, 0);
  assert.equal(result.counts.truePositives, config.trials);
  assert.equal(result.metrics.decisionCoverage, 1);
  assert.deepEqual(result.metrics.fprComposite95CI.length, 2);
  assert.equal(result.counts.contentUnobserved, config.trials * 2);
  assert.ok(result.metrics.simulatedCostMsPerTrial > 0);
});

test("timeout and invalid jitter budgets are refused", () => {
  assert.throws(
    () => benchmarkTimingScenario({ ...config, trials: 0 }),
    /Trials must be/,
  );
  assert.throws(
    () => benchmarkTimingScenario({ ...config, sigma: -1 }),
    /Jitter scale is invalid/,
  );
  assert.throws(
    () =>
      virtualTimingTrial(
        { ...config, samples: 2, vulnerable: false },
        () => 0.5,
      ),
    /Sample count must be/,
  );
});

test("supported heavy-tail and drift modes return explicit metrics", () => {
  for (const distribution of ["lognormal", "bimodal", "drift", "correlated"]) {
    const report = benchmarkTimingScenario({ ...config, distribution });
    assert.equal(report.counts.trialsPerClass, config.trials);
    assert.ok(report.metrics.decisionCoverage >= 0);
    assert.ok(report.metrics.fprComposite >= 0);
    assert.ok(report.metrics.simulatedCostMsPerTrial > 0);
  }
});
