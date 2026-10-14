import { performance } from "node:perf_hooks";
import { finding } from "./findings.js";
import type {
  Config,
  ScanResult,
  Severity,
  TimingDifferentialConfig,
  TimingDifferentialExperimentResult,
  TimingDifferentialMeasurementSet,
  TimingDifferentialRequest,
  TimingDifferentialReport,
} from "./model.js";

const COOKIE_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const ENV_NAME = /^[A-Z_][A-Z0-9_]*$/i;
const EXPERIMENT_ID = /^[a-z0-9][a-z0-9._-]{1,63}$/i;
const REDIRECTS = new Set([301, 302, 303, 307, 308]);

function isLoopbackHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (normalized === "localhost" || normalized === "::1") return true;
  const match = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(normalized);
  return Boolean(match && Number(match[1]) === 127);
}

function assertLocalTarget(value: string): URL {
  let target: URL;
  try {
    target = new URL(value);
  } catch {
    throw new Error("Timing differential target must be a valid URL.");
  }
  if (!["http:", "https:"].includes(target.protocol))
    throw new Error("Timing differential target must use HTTP(S).");
  if (target.username || target.password || target.hash)
    throw new Error(
      "Timing differential target cannot contain credentials or a fragment.",
    );
  if (!isLoopbackHostname(target.hostname))
    throw new Error(
      "Timing differential execution is restricted to localhost/loopback laboratory targets.",
    );
  return target;
}

function requestSpec(value: unknown, label: string): TimingDifferentialRequest {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error(`${label} must be an object.`);
  const item = value as Record<string, unknown>;
  for (const key of Object.keys(item))
    if (!["path", "method", "query"].includes(key))
      throw new Error(`Unknown ${label} key: ${key}`);

  if (
    item.path !== undefined &&
    (typeof item.path !== "string" ||
      !item.path.startsWith("/") ||
      item.path.startsWith("//"))
  )
    throw new Error(`${label}.path must be an origin-relative path.`);

  if (
    item.method !== undefined &&
    !["GET", "HEAD"].includes(String(item.method))
  )
    throw new Error(`${label}.method must be GET or HEAD.`);

  if (item.query !== undefined) {
    if (
      !item.query ||
      typeof item.query !== "object" ||
      Array.isArray(item.query) ||
      !Object.entries(item.query as Record<string, unknown>).every(
        ([key, entry]) =>
          key.length > 0 &&
          key.length <= 200 &&
          typeof entry === "string" &&
          entry.length <= 4096,
      )
    )
      throw new Error(
        `${label}.query must map query names to bounded strings.`,
      );
  }

  return item as unknown as TimingDifferentialRequest;
}

export function validateTimingDifferentialConfig(
  value: unknown,
): TimingDifferentialConfig {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("timing must be an object.");
  const timing = value as Record<string, unknown>;
  const allowed = new Set([
    "authorization",
    "samples",
    "timeoutMs",
    "thresholdRatio",
    "minDeltaMs",
    "cookieEnvs",
    "responseMustInclude",
    "baseline",
    "experiments",
  ]);
  for (const key of Object.keys(timing))
    if (!allowed.has(key)) throw new Error(`Unknown timing key: ${key}`);

  if (
    !timing.authorization ||
    typeof timing.authorization !== "object" ||
    Array.isArray(timing.authorization)
  )
    throw new Error("timing.authorization is required.");
  const authorization = timing.authorization as Record<string, unknown>;
  for (const key of Object.keys(authorization))
    if (!["acknowledged", "reference"].includes(key))
      throw new Error(`Unknown timing.authorization key: ${key}`);
  if (authorization.acknowledged !== true)
    throw new Error("timing.authorization.acknowledged must be true.");
  if (
    typeof authorization.reference !== "string" ||
    authorization.reference.trim().length < 3 ||
    authorization.reference.length > 200
  )
    throw new Error("timing.authorization.reference is required.");

  const samples = timing.samples ?? 5;
  if (
    !Number.isSafeInteger(samples) ||
    Number(samples) < 3 ||
    Number(samples) > 9
  )
    throw new Error("timing.samples must be between 3 and 9.");

  const timeoutMs = timing.timeoutMs ?? 10_000;
  if (
    !Number.isSafeInteger(timeoutMs) ||
    Number(timeoutMs) < 100 ||
    Number(timeoutMs) > 30_000
  )
    throw new Error("timing.timeoutMs must be between 100 and 30000.");

  const thresholdRatio = timing.thresholdRatio ?? 0.8;
  if (
    typeof thresholdRatio !== "number" ||
    !Number.isFinite(thresholdRatio) ||
    thresholdRatio < 0.5 ||
    thresholdRatio > 1
  )
    throw new Error("timing.thresholdRatio must be between 0.5 and 1.");

  const minDeltaMs = timing.minDeltaMs ?? 500;
  if (
    !Number.isSafeInteger(minDeltaMs) ||
    Number(minDeltaMs) < 50 ||
    Number(minDeltaMs) > 10_000
  )
    throw new Error("timing.minDeltaMs must be between 50 and 10000.");

  if (timing.cookieEnvs !== undefined) {
    if (
      !timing.cookieEnvs ||
      typeof timing.cookieEnvs !== "object" ||
      Array.isArray(timing.cookieEnvs)
    )
      throw new Error("timing.cookieEnvs must be an object.");
    for (const [cookie, env] of Object.entries(
      timing.cookieEnvs as Record<string, unknown>,
    )) {
      if (!COOKIE_NAME.test(cookie))
        throw new Error("timing.cookieEnvs contains an invalid cookie name.");
      if (typeof env !== "string" || !ENV_NAME.test(env))
        throw new Error(
          "timing.cookieEnvs values must be environment variable names.",
        );
    }
  }

  if (timing.responseMustInclude !== undefined) {
    if (
      !Array.isArray(timing.responseMustInclude) ||
      timing.responseMustInclude.length < 1 ||
      timing.responseMustInclude.length > 10 ||
      !timing.responseMustInclude.every(
        (entry) =>
          typeof entry === "string" && entry.length >= 1 && entry.length <= 200,
      )
    )
      throw new Error(
        "timing.responseMustInclude must contain 1 to 10 bounded strings.",
      );
  }

  requestSpec(timing.baseline, "timing.baseline");

  if (
    !Array.isArray(timing.experiments) ||
    timing.experiments.length < 1 ||
    timing.experiments.length > 8
  )
    throw new Error("timing.experiments must contain 1 to 8 experiments.");

  const ids = new Set<string>();
  for (const [index, raw] of timing.experiments.entries()) {
    const label = `timing.experiments[${index}]`;
    if (!raw || typeof raw !== "object" || Array.isArray(raw))
      throw new Error(`${label} must be an object.`);
    const item = raw as Record<string, unknown>;
    for (const key of Object.keys(item))
      if (
        ![
          "id",
          "title",
          "severity",
          "expectedDelayMs",
          "negative",
          "positive",
        ].includes(key)
      )
        throw new Error(`Unknown ${label} key: ${key}`);

    if (typeof item.id !== "string" || !EXPERIMENT_ID.test(item.id))
      throw new Error(`${label}.id is invalid.`);
    if (ids.has(item.id))
      throw new Error(`Duplicate timing experiment id: ${item.id}`);
    ids.add(item.id);

    if (
      typeof item.title !== "string" ||
      item.title.trim().length < 3 ||
      item.title.length > 200
    )
      throw new Error(`${label}.title is required.`);

    if (
      item.severity !== undefined &&
      !["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].includes(
        String(item.severity),
      )
    )
      throw new Error(`${label}.severity is invalid.`);

    if (
      !Number.isSafeInteger(item.expectedDelayMs) ||
      Number(item.expectedDelayMs) < 100 ||
      Number(item.expectedDelayMs) > 15_000
    )
      throw new Error(
        `${label}.expectedDelayMs must be between 100 and 15000.`,
      );

    requestSpec(item.negative, `${label}.negative`);
    requestSpec(item.positive, `${label}.positive`);
  }

  const requestBudget = Number(samples) * (1 + 2 * timing.experiments.length);
  if (requestBudget > 153)
    throw new Error(
      "timing configuration exceeds the 153-request laboratory cap.",
    );

  return timing as unknown as TimingDifferentialConfig;
}

function median(values: number[]): number | undefined {
  if (values.length === 0) return undefined;
  const ordered = [...values].sort((a, b) => a - b);
  const middle = Math.floor(ordered.length / 2);
  return ordered.length % 2 === 1
    ? ordered[middle]
    : (ordered[middle - 1]! + ordered[middle]!) / 2;
}

function measurementSet(
  durationsMs: number[],
  timeouts: number,
  errors: number,
): TimingDifferentialMeasurementSet {
  const med = median(durationsMs);
  const mad =
    med === undefined
      ? undefined
      : median(durationsMs.map((value) => Math.abs(value - med)));
  return {
    durationsMs: durationsMs.map((value) => Math.round(value)),
    timeouts,
    errors,
    successfulSamples: durationsMs.length,
    totalSamples: durationsMs.length + timeouts + errors,
    ...(med === undefined ? {} : { medianMs: Math.round(med) }),
    ...(mad === undefined ? {} : { madMs: Math.round(mad) }),
  };
}

function timeoutRatio(value: TimingDifferentialMeasurementSet): number {
  return value.totalSamples === 0 ? 0 : value.timeouts / value.totalSamples;
}

function requestUrl(target: URL, spec: TimingDifferentialRequest): URL {
  const url = spec.path
    ? new URL(spec.path, target.origin)
    : new URL(target.toString());
  if (url.origin !== target.origin)
    throw new Error("Timing request escaped the local target origin.");
  for (const [key, value] of Object.entries(spec.query ?? {}))
    url.searchParams.set(key, value);
  return url;
}

function cookieHeader(config: TimingDifferentialConfig): string | undefined {
  const values: string[] = [];
  for (const [cookie, envName] of Object.entries(config.cookieEnvs ?? {})) {
    const value = process.env[envName];
    if (!value)
      throw new Error(
        `Timing cookie environment variable ${envName} is not set.`,
      );
    if (Buffer.byteLength(value, "utf8") > 4096 || /[\r\n;]/.test(value))
      throw new Error(
        `Timing cookie environment variable ${envName} is unsafe.`,
      );
    values.push(`${cookie}=${value}`);
  }
  return values.length ? values.join("; ") : undefined;
}

type SampleResult =
  | { kind: "duration"; durationMs: number }
  | { kind: "timeout" }
  | { kind: "error"; message: string };

async function measure(
  target: URL,
  spec: TimingDifferentialRequest,
  config: TimingDifferentialConfig,
  signal?: AbortSignal,
): Promise<SampleResult> {
  const url = requestUrl(target, spec);
  const timeout = AbortSignal.timeout(config.timeoutMs ?? 10_000);
  const combined = signal ? AbortSignal.any([signal, timeout]) : timeout;
  const headers = new Headers({
    accept: "text/html,application/xhtml+xml,application/json,text/plain;q=0.8",
    "user-agent": "REAPER/0.2.0 local-timing-differential",
  });
  const cookie = cookieHeader(config);
  if (cookie) headers.set("cookie", cookie);

  const started = performance.now();
  try {
    const response = await fetch(url, {
      method: spec.method ?? "GET",
      headers,
      redirect: "manual",
      signal: combined,
    });
    const elapsed = performance.now() - started;

    if (REDIRECTS.has(response.status)) {
      await response.body?.cancel().catch(() => {});
      return {
        kind: "error",
        message: `unexpected HTTP redirect ${response.status}`,
      };
    }
    if (response.status >= 500) {
      await response.body?.cancel().catch(() => {});
      return { kind: "error", message: `unexpected HTTP ${response.status}` };
    }

    if (
      (config.responseMustInclude?.length ?? 0) > 0 &&
      spec.method !== "HEAD"
    ) {
      const contentLength = Number(
        response.headers.get("content-length") ?? "0",
      );
      if (Number.isFinite(contentLength) && contentLength > 1_048_576) {
        await response.body?.cancel().catch(() => {});
        return { kind: "error", message: "response body exceeds 1 MiB" };
      }
      const text = await response.text();
      if (Buffer.byteLength(text, "utf8") > 1_048_576)
        return { kind: "error", message: "response body exceeds 1 MiB" };
      for (const expected of config.responseMustInclude ?? [])
        if (!text.includes(expected))
          return {
            kind: "error",
            message: `response did not contain required marker ${JSON.stringify(expected)}`,
          };
    } else {
      await response.body?.cancel().catch(() => {});
    }
    return { kind: "duration", durationMs: elapsed };
  } catch (error) {
    if (combined.aborted) {
      if (signal?.aborted)
        throw new Error("Timing differential run cancelled.");
      return { kind: "timeout" };
    }
    return {
      kind: "error",
      message: error instanceof Error ? error.message : "request failed",
    };
  }
}

async function collect(
  target: URL,
  spec: TimingDifferentialRequest,
  config: TimingDifferentialConfig,
  samples: number,
  signal?: AbortSignal,
): Promise<TimingDifferentialMeasurementSet> {
  const durations: number[] = [];
  let timeouts = 0;
  let errors = 0;
  for (let index = 0; index < samples; index++) {
    if (signal?.aborted) throw new Error("Timing differential run cancelled.");
    const result = await measure(target, spec, config, signal);
    if (result.kind === "duration") durations.push(result.durationMs);
    else if (result.kind === "timeout") timeouts++;
    else errors++;
  }
  return measurementSet(durations, timeouts, errors);
}

async function collectPair(
  target: URL,
  negative: TimingDifferentialRequest,
  positive: TimingDifferentialRequest,
  config: TimingDifferentialConfig,
  samples: number,
  signal?: AbortSignal,
): Promise<{
  negative: TimingDifferentialMeasurementSet;
  positive: TimingDifferentialMeasurementSet;
}> {
  const negativeDurations: number[] = [];
  const positiveDurations: number[] = [];
  let negativeTimeouts = 0;
  let positiveTimeouts = 0;
  let negativeErrors = 0;
  let positiveErrors = 0;

  const record = (
    result: SampleResult,
    durations: number[],
    timeout: () => void,
    error: () => void,
  ) => {
    if (result.kind === "duration") durations.push(result.durationMs);
    else if (result.kind === "timeout") timeout();
    else error();
  };

  for (let index = 0; index < samples; index++) {
    const order =
      index % 2 === 0
        ? ([
            ["negative", negative],
            ["positive", positive],
          ] as const)
        : ([
            ["positive", positive],
            ["negative", negative],
          ] as const);

    for (const [kind, spec] of order) {
      if (signal?.aborted)
        throw new Error("Timing differential run cancelled.");
      const result = await measure(target, spec, config, signal);
      if (kind === "negative")
        record(
          result,
          negativeDurations,
          () => negativeTimeouts++,
          () => negativeErrors++,
        );
      else
        record(
          result,
          positiveDurations,
          () => positiveTimeouts++,
          () => positiveErrors++,
        );
    }
  }

  return {
    negative: measurementSet(
      negativeDurations,
      negativeTimeouts,
      negativeErrors,
    ),
    positive: measurementSet(
      positiveDurations,
      positiveTimeouts,
      positiveErrors,
    ),
  };
}

function analyze(
  baseline: TimingDifferentialMeasurementSet,
  negative: TimingDifferentialMeasurementSet,
  positive: TimingDifferentialMeasurementSet,
  expectedDelayMs: number,
  config: TimingDifferentialConfig,
): Pick<
  TimingDifferentialExperimentResult,
  "confirmed" | "confidence" | "reason" | "deltaMs" | "thresholdMs" | "jitterMs"
> {
  const positiveTimeoutRatio = timeoutRatio(positive);
  const negativeTimeoutRatio = timeoutRatio(negative);

  if (
    positiveTimeoutRatio >= 0.6 &&
    negativeTimeoutRatio <= 0.2 &&
    timeoutRatio(baseline) <= 0.2
  )
    return {
      confirmed: true,
      confidence: "HIGH",
      reason:
        "positive control repeatedly exceeded the observation timeout while baseline and negative control remained responsive",
    };

  const requiredSuccessful = Math.ceil((config.samples ?? 5) * 0.6);
  if (
    baseline.medianMs === undefined ||
    negative.medianMs === undefined ||
    positive.medianMs === undefined ||
    baseline.successfulSamples < requiredSuccessful ||
    negative.successfulSamples < requiredSuccessful ||
    positive.successfulSamples < requiredSuccessful
  )
    return {
      confirmed: false,
      confidence: "INCONCLUSIVE",
      reason: "insufficient successful samples for a reliable differential",
    };

  const deltaMs = positive.medianMs - negative.medianMs;
  const jitterMs = Math.max(baseline.madMs ?? 0, negative.madMs ?? 0);
  const thresholdMs = Math.round(
    Math.max(
      expectedDelayMs * (config.thresholdRatio ?? 0.8),
      jitterMs * 6,
      config.minDeltaMs ?? 500,
    ),
  );
  const negativeDriftMs = Math.abs(negative.medianMs - baseline.medianMs);
  const driftLimitMs = Math.max(1000, expectedDelayMs * 0.25, jitterMs * 6);

  if (negativeDriftMs > driftLimitMs)
    return {
      confirmed: false,
      confidence: "INCONCLUSIVE",
      reason:
        "negative control drifted too far from baseline; repeat after stabilizing the local laboratory",
      deltaMs,
      thresholdMs,
      jitterMs,
    };

  if (deltaMs < thresholdMs)
    return {
      confirmed: false,
      confidence: "LOW",
      reason:
        "positive/negative timing delta did not cross the evidence threshold",
      deltaMs,
      thresholdMs,
      jitterMs,
    };

  const high =
    deltaMs >= expectedDelayMs * 0.9 &&
    jitterMs <= Math.max(250, expectedDelayMs * 0.05) &&
    negative.timeouts === 0;

  return {
    confirmed: true,
    confidence: high ? "HIGH" : "MEDIUM",
    reason:
      "positive/negative timing delta is consistent with the configured delay and exceeds observed jitter",
    deltaMs,
    thresholdMs,
    jitterMs,
  };
}

function resultFor(target: URL): ScanResult {
  return {
    version: "0.2.0",
    root: target.toString(),
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
    coverage: { source: false, database: false, runtime: true },
  };
}

export async function runTimingDifferential(
  target: string,
  config: Config | TimingDifferentialConfig,
  options: { signal?: AbortSignal } = {},
): Promise<ScanResult> {
  const parsed = assertLocalTarget(target);
  const raw =
    "timing" in config
      ? (config as Config).timing
      : (config as TimingDifferentialConfig);
  if (!raw)
    throw new Error("Timing differential mode requires timing configuration.");
  const timing = validateTimingDifferentialConfig(raw);
  const samples = timing.samples ?? 5;
  const startedAt = new Date().toISOString();
  const started = performance.now();
  const result = resultFor(parsed);

  const baseline = await collect(
    parsed,
    timing.baseline,
    timing,
    samples,
    options.signal,
  );
  const experiments: TimingDifferentialExperimentResult[] = [];

  for (const experiment of timing.experiments) {
    const pair = await collectPair(
      parsed,
      experiment.negative,
      experiment.positive,
      timing,
      samples,
      options.signal,
    );
    const analysis = analyze(
      baseline,
      pair.negative,
      pair.positive,
      experiment.expectedDelayMs,
      timing,
    );
    const item: TimingDifferentialExperimentResult = {
      id: experiment.id,
      title: experiment.title,
      expectedDelayMs: experiment.expectedDelayMs,
      negative: pair.negative,
      positive: pair.positive,
      ...analysis,
    };
    experiments.push(item);

    if (item.confirmed) {
      const created = finding(
        {
          ruleId: "REAPER-TIMING-001",
          title:
            "Timing differential indicates a reproducible delayed execution path",
          description:
            "A localhost-only paired timing experiment produced a positive/negative response-time delta consistent with the configured delay.",
          severity: experiment.severity ?? ("HIGH" as Severity),
          confidence: item.confidence === "HIGH" ? "HIGH" : "MEDIUM",
          category: "Offensive Validation",
          file: `runtime:timing:${experiment.id}`,
          line: 1,
          column: 1,
          route: `${experiment.positive.method ?? "GET"} ${experiment.positive.path ?? parsed.pathname}`,
          evidence: [
            `Authorization reference: ${timing.authorization.reference}`,
            `Experiment: ${experiment.title}`,
            `Samples per control: ${samples}`,
            `Baseline median: ${baseline.medianMs ?? "n/a"} ms`,
            `Negative median: ${pair.negative.medianMs ?? "n/a"} ms`,
            `Positive median: ${pair.positive.medianMs ?? "n/a"} ms`,
            ...(item.deltaMs === undefined
              ? []
              : [`Delta: ${item.deltaMs} ms`]),
            ...(item.thresholdMs === undefined
              ? []
              : [`Evidence threshold: ${item.thresholdMs} ms`]),
            ...(item.jitterMs === undefined
              ? []
              : [`Observed MAD jitter: ${item.jitterMs} ms`]),
            `Confidence: ${item.confidence}`,
            `Reason: ${item.reason}`,
          ],
          dataFlow: [],
          recommendation:
            "Treat the delayed branch as reproducible laboratory evidence, identify the input-to-query data flow, parameterize the database operation, and keep this paired timing experiment as a regression test.",
        },
        `${parsed.origin}:${experiment.id}:${item.deltaMs ?? "timeout"}`,
      );
      result.findings.push(created);
    } else if (item.confidence === "INCONCLUSIVE") {
      result.diagnostics.push({
        message: `Timing experiment ${experiment.id} is inconclusive: ${item.reason}.`,
      });
    }
  }

  const completedAt = new Date().toISOString();
  const report: TimingDifferentialReport = {
    version: 1,
    target: parsed.toString(),
    authorizationReference: timing.authorization.reference,
    startedAt,
    completedAt,
    samples,
    timeoutMs: timing.timeoutMs ?? 10_000,
    baseline,
    experiments,
    confirmedCount: experiments.filter((item) => item.confirmed).length,
    highConfidenceCount: experiments.filter(
      (item) => item.confirmed && item.confidence === "HIGH",
    ).length,
  };
  result.timing = report;
  result.metrics.sinks =
    baseline.totalSamples +
    experiments.reduce(
      (total, item) =>
        total + item.negative.totalSamples + item.positive.totalSamples,
      0,
    );
  result.metrics.durationMs = Math.round(performance.now() - started);
  result.metrics.memoryBytes = process.memoryUsage().rss;
  return result;
}
