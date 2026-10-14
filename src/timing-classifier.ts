import type { TimingMeasurementSet } from "./timing-sqli.js";

export const TIMING_REASON_SCHEMA_VERSION = 1 as const;

export type TimingReasonCodeV1 =
  | "POSITIVE_TIMEOUT_HEALTHY_CONTROLS"
  | "INCOMPLETE_OR_UNHEALTHY_CONTROLS"
  | "DIFFERENTIAL_ABOVE_THRESHOLD"
  | "DIFFERENTIAL_BELOW_THRESHOLD";

export type TimingObservationOutcome =
  | "ok"
  | "timeout"
  | "http-error"
  | "marker-mismatch"
  | "transport-error";

export interface TimingObservation {
  role: "baseline" | "negative" | "positive";
  order: number;
  outcome: TimingObservationOutcome;
  elapsedMs?: number;
  httpStatus?: number;
  bodyBytes?: number;
  normalizedBodyHash?: string;
  markerMatched?: boolean;
}

export interface TimingClassification {
  confirmed: boolean;
  confidence: "HIGH" | "MEDIUM" | "LOW" | "INCONCLUSIVE";
  reason: string;
  reasonSchemaVersion: typeof TIMING_REASON_SCHEMA_VERSION;
  reasonCode: TimingReasonCodeV1;
  deltaMs?: number;
  thresholdMs?: number;
  observedJitterMs?: number;
}

function median(values: number[]): number | undefined {
  if (!values.length) return undefined;
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  if (sorted.length % 2) return sorted[middle];
  return (sorted[middle - 1]! + sorted[middle]!) / 2;
}

export function summarizeTimingObservations(
  observations: readonly TimingObservation[],
  role: TimingObservation["role"],
): TimingMeasurementSet {
  const timesMs: number[] = [];
  let timeouts = 0;
  let errors = 0;

  for (const item of observations) {
    if (item.role !== role) continue;
    if (!Number.isSafeInteger(item.order) || item.order < 0)
      throw new Error("Timing observation order is invalid.");
    if (item.outcome === "timeout") {
      timeouts++;
    } else if (
      item.outcome === "http-error" ||
      item.outcome === "marker-mismatch" ||
      item.outcome === "transport-error"
    ) {
      errors++;
    } else if (
      item.outcome === "ok" &&
      typeof item.elapsedMs === "number" &&
      Number.isFinite(item.elapsedMs) &&
      item.elapsedMs >= 0 &&
      (item.httpStatus === undefined || item.httpStatus === 200) &&
      item.markerMatched !== false
    ) {
      timesMs.push(item.elapsedMs);
    } else {
      throw new Error("Timing observation metadata is inconsistent.");
    }
  }
  const medianMs = median(timesMs);
  return {
    timesMs,
    timeouts,
    errors,
    ...(medianMs === undefined
      ? {}
      : {
          medianMs,
          madMs: median(timesMs.map((value) => Math.abs(value - medianMs))),
        }),
  };
}

export function classifyTimingMeasurements(
  baseline: TimingMeasurementSet,
  negative: TimingMeasurementSet,
  positive: TimingMeasurementSet,
  expectedDelayMs: number,
): TimingClassification {
  if (!Number.isFinite(expectedDelayMs) || expectedDelayMs <= 0)
    throw new Error("Expected timing delay must be positive.");

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
      reasonSchemaVersion: TIMING_REASON_SCHEMA_VERSION,
      reasonCode: "POSITIVE_TIMEOUT_HEALTHY_CONTROLS",
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
      reasonSchemaVersion: TIMING_REASON_SCHEMA_VERSION,
      reasonCode: "INCOMPLETE_OR_UNHEALTHY_CONTROLS",
      reason: "Insufficient valid samples for differential timing analysis.",
    };
  }

  const deltaMs = positive.medianMs - negative.medianMs;
  const observedJitterMs = Math.max(baseline.madMs ?? 0, negative.madMs ?? 0);
  // Equivalent to the historical max(0.8D, 6*MAD, min(500, 0.25D)).
  // The final term was mathematically unreachable; keep behavior unchanged
  // while an empirical benchmark establishes whether the threshold should change.
  const thresholdMs = Math.max(expectedDelayMs * 0.8, observedJitterMs * 6);
  const confirmed = deltaMs >= thresholdMs;
  const confidence = confirmed
    ? observedJitterMs < 250 && deltaMs >= expectedDelayMs * 0.9
      ? "HIGH"
      : "MEDIUM"
    : "LOW";

  return {
    confirmed,
    confidence,
    reasonSchemaVersion: TIMING_REASON_SCHEMA_VERSION,
    reasonCode: confirmed
      ? "DIFFERENTIAL_ABOVE_THRESHOLD"
      : "DIFFERENTIAL_BELOW_THRESHOLD",
    reason: confirmed
      ? "Positive/negative timing delta is consistent with the expected delay."
      : "Observed timing delta is below the required differential threshold.",
    deltaMs,
    thresholdMs,
    observedJitterMs,
  };
}

export function classifyTimingObservations(
  observations: readonly TimingObservation[],
  expectedDelayMs: number,
): TimingClassification {
  return classifyTimingMeasurements(
    summarizeTimingObservations(observations, "baseline"),
    summarizeTimingObservations(observations, "negative"),
    summarizeTimingObservations(observations, "positive"),
    expectedDelayMs,
  );
}

export function contentEffectDiagnostic(
  observations: readonly TimingObservation[],
): "CONTENT_EFFECT_OBSERVED" | "CONTENT_EFFECT_UNOBSERVED" | "CONTENT_NOT_MEASURED" {
  const relevant = observations.filter(
    (sample) =>
      sample.outcome === "ok" &&
      (sample.role === "baseline" || sample.role === "negative"),
  );
  if (
    !relevant.some((item) => item.role === "baseline") ||
    !relevant.some((item) => item.role === "negative") ||
    relevant.some((item) => !item.normalizedBodyHash)
  )
    return "CONTENT_NOT_MEASURED";
  return new Set(relevant.map((item) => item.normalizedBodyHash)).size > 1
    ? "CONTENT_EFFECT_OBSERVED"
    : "CONTENT_EFFECT_UNOBSERVED";
}

// Drift is intentionally a separate order-sensitive diagnostic. It never
// changes the classification, which is invariant to collection order.
export function timingDriftDiagnostic(
  observations: readonly TimingObservation[],
): number | undefined {
  const valid = observations
    .filter(
      (item) =>
        item.outcome === "ok" &&
        typeof item.elapsedMs === "number" &&
        Number.isFinite(item.elapsedMs),
    )
    .sort((a, b) => a.order - b.order);
  if (valid.length < 4) return undefined;
  const half = Math.floor(valid.length / 2);
  const early = median(valid.slice(0, half).map((item) => item.elapsedMs!));
  const late = median(valid.slice(-half).map((item) => item.elapsedMs!));
  return early === undefined || late === undefined ? undefined : late - early;
}
