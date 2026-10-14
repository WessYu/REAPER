import { pathToFileURL } from "node:url";
import {
  classifyTimingObservations,
  summarizeTimingObservations,
  contentEffectDiagnostic,
} from "../dist/index.js";

function seededRandom(seed) {
  if (!Number.isSafeInteger(seed) || seed === 0)
    throw new Error("Seed must be a nonzero safe integer.");
  let state = seed >>> 0;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) / 4294967296;
  };
}

function gaussian(random) {
  return (
    Math.sqrt(-2 * Math.log(Math.max(Number.EPSILON, random()))) *
    Math.cos(2 * Math.PI * random())
  );
}

function jitterSource(distribution, sigmaMs, random) {
  let correlatedSpike = 0;
  return (order, total) => {
    if (distribution === "uniform")
      return (random() * 2 - 1) * sigmaMs * Math.sqrt(3);
    if (distribution === "gaussian") return gaussian(random) * sigmaMs;
    if (distribution === "lognormal") {
      const z = gaussian(random);
      const width = 0.7;
      return (Math.exp(width * z) - Math.exp((width * width) / 2)) * sigmaMs;
    }
    if (distribution === "bimodal")
      return (random() < 0.13 ? 2.5 : -0.3736) * sigmaMs;
    if (distribution === "drift")
      return (
        gaussian(random) * sigmaMs * (0.4 + order / total) +
        (order / total) * sigmaMs
      );
    if (distribution === "correlated") {
      if (correlatedSpike > 0) correlatedSpike--;
      else if (random() < 0.08) correlatedSpike = 2;
      return (
        gaussian(random) * sigmaMs * 0.3 +
        (correlatedSpike > 0 ? sigmaMs * 4 : 0)
      );
    }
    throw new Error("Unknown jitter distribution.");
  };
}

export function virtualTimingTrial(options, random) {
  const {
    samples,
    expectedDelayMs,
    sigma,
    jitterRegime,
    distribution,
    vulnerable,
  } = options;
  if (![3, 5, 7, 9].includes(samples))
    throw new Error("Sample count must be 3, 5, 7 or 9.");
  if (!Number.isFinite(expectedDelayMs) || expectedDelayMs < 50)
    throw new Error("Expected delay is invalid.");
  if (!Number.isFinite(sigma) || sigma < 0)
    throw new Error("Jitter scale is invalid.");
  if (!["abs", "prop"].includes(jitterRegime))
    throw new Error("Jitter regime is invalid.");

  const sigmaMs = jitterRegime === "prop" ? expectedDelayMs * sigma : sigma;
  const jitter = jitterSource(distribution, sigmaMs, random);
  const timeoutMs = expectedDelayMs + Math.max(500, sigmaMs * 8);
  const total = samples * 3;
  const observations = [];
  let costMs = 0;

  const observe = (role) => {
    const order = observations.length;
    const delay = role === "positive" && vulnerable ? expectedDelayMs : 0;
    const latencyMs = Math.max(0.1, 40 + delay + jitter(order, total));
    const timedOut = latencyMs >= timeoutMs;
    costMs += Math.min(latencyMs, timeoutMs);
    observations.push({
      role,
      order,
      outcome: timedOut ? "timeout" : "ok",
      ...(timedOut
        ? {}
        : {
            elapsedMs: latencyMs,
            httpStatus: 200,
            markerMatched: true,
            bodyBytes: 64,
            normalizedBodyHash: "constant-html",
          }),
    });
  };

  for (let i = 0; i < samples; i++) observe("baseline");
  for (let i = 0; i < samples; i++) {
    if (i % 2 === 0) {
      observe("negative");
      observe("positive");
    } else {
      observe("positive");
      observe("negative");
    }
  }
  const classification = classifyTimingObservations(
    observations,
    expectedDelayMs,
  );
  const baseline = summarizeTimingObservations(observations, "baseline");
  return {
    classification,
    costMs,
    contentEffect: contentEffectDiagnostic(observations),
    // Diagnostic only: baseline latency is not the detector's decision rule.
    baselineAlarm: (baseline.medianMs ?? 0) > expectedDelayMs * 0.8,
  };
}

function wilson(successes, total) {
  if (!total) return null;
  const p = successes / total;
  const z = 1.959963984540054;
  const d = 1 + (z * z) / total;
  const center = (p + (z * z) / (2 * total)) / d;
  const margin =
    (z * Math.sqrt((p * (1 - p)) / total + (z * z) / (4 * total * total))) / d;
  return [Math.max(0, center - margin), Math.min(1, center + margin)];
}

function divide(num, denom) {
  return denom ? num / denom : null;
}

export function benchmarkTimingScenario(options) {
  const { trials, seed } = options;
  if (!Number.isSafeInteger(trials) || trials < 1 || trials > 100_000)
    throw new Error("Trials must be between 1 and 100000.");
  const random = seededRandom(seed);
  let falsePositives = 0;
  let truePositives = 0;
  let decidedNegative = 0;
  let decidedPositive = 0;
  let controlAlarms = 0;
  let contentUnobserved = 0;
  let totalCostMs = 0;
  let totalDecidedCostMs = 0;
  let decisions = 0;
  const reasons = Object.create(null);

  for (const vulnerable of [false, true]) {
    for (let trial = 0; trial < trials; trial++) {
      const result = virtualTimingTrial({ ...options, vulnerable }, random);
      const decision = result.classification;
      reasons[decision.reasonCode] = (reasons[decision.reasonCode] ?? 0) + 1;
      totalCostMs += result.costMs;
      if (result.baselineAlarm) controlAlarms++;
      if (result.contentEffect === "CONTENT_EFFECT_UNOBSERVED")
        contentUnobserved++;
      const decisive = decision.confidence !== "INCONCLUSIVE";
      if (decisive) {
        decisions++;
        totalDecidedCostMs += result.costMs;
        if (vulnerable) decidedPositive++;
        else decidedNegative++;
      }
      if (decision.confirmed && vulnerable) truePositives++;
      if (decision.confirmed && !vulnerable) falsePositives++;
    }
  }

  return {
    scenario: {
      distribution: options.distribution,
      jitterRegime: options.jitterRegime,
      sigma: options.sigma,
      expectedDelayMs: options.expectedDelayMs,
      samples: options.samples,
      seed,
      trialsPerClass: trials,
    },
    counts: {
      truePositives,
      falsePositives,
      decidedPositive,
      decidedNegative,
      trialsPerClass: trials,
      contentUnobserved,
    },
    metrics: {
      tprComposite: truePositives / trials,
      fprComposite: falsePositives / trials,
      fprComposite95CI: wilson(falsePositives, trials),
      fprAmongDecisions: divide(falsePositives, decidedNegative),
      decisionCoverage: decisions / (2 * trials),
      decisionCoverageNegative: decidedNegative / trials,
      decisionCoveragePositive: decidedPositive / trials,
      inconclusiveRate: 1 - decisions / (2 * trials),
      baselineAlarmRate: controlAlarms / (2 * trials),
      simulatedCostMsPerTrial: totalCostMs / (2 * trials),
      simulatedCostMsPerDecision: divide(totalDecidedCostMs, decisions),
    },
    reasonCounts: reasons,
    note: "Virtual additive jitter is not wall-clock latency; equal response bodies are retained in all eligible ground-truth trials.",
  };
}

async function main() {
  const trials = Number(process.env.REAPER_TIMING_TRIALS ?? 200);
  const seed = Number(process.env.REAPER_TIMING_SEED ?? 20261014);
  const distributions = [
    "uniform",
    "gaussian",
    "lognormal",
    "bimodal",
    "drift",
    "correlated",
  ];
  const scenarios = [];
  for (const expectedDelayMs of [500, 1000, 5000]) {
    for (const samples of [3, 5, 7, 9]) {
      for (const distribution of distributions) {
        for (const jitterRegime of ["abs", "prop"]) {
          const sigma = jitterRegime === "abs" ? 50 : 0.1;
          scenarios.push(
            benchmarkTimingScenario({
              trials,
              seed,
              samples,
              expectedDelayMs,
              sigma,
              jitterRegime,
              distribution,
            }),
          );
        }
      }
    }
  }
  process.stdout.write(
    JSON.stringify(
      {
        schemaVersion: 1,
        model:
          "Offline additive virtual jitter; i.i.d. only for uniform, gaussian and lognormal. Correlated/drift modes violate i.i.d.",
        caveat:
          "These are simulated observations, not scans or empirical real-world detection rates. Compare separately against the actual localhost HTTP fixture.",
        scenarios,
      },
      null,
      2,
    ) + "\n",
  );
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 2;
  });
}
