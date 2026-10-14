import test from "node:test";
import assert from "node:assert/strict";
import {
  analyzeTimingDifferential,
  renderTimingLab,
  runLocalTimingDifferentialLab,
} from "../dist/index.js";

function set(timesMs, timeouts = 0, errors = 0) {
  const ordered = [...timesMs].sort((a, b) => a - b);
  const middle = Math.floor(ordered.length / 2);
  const medianMs =
    ordered.length === 0
      ? undefined
      : ordered.length % 2
        ? ordered[middle]
        : (ordered[middle - 1] + ordered[middle]) / 2;
  const deviations =
    medianMs === undefined
      ? []
      : ordered.map((value) => Math.abs(value - medianMs)).sort((a, b) => a - b);
  const dm = Math.floor(deviations.length / 2);
  const madMs =
    deviations.length === 0
      ? undefined
      : deviations.length % 2
        ? deviations[dm]
        : (deviations[dm - 1] + deviations[dm]) / 2;
  const totalSamples = timesMs.length + timeouts + errors;
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

test("timing differential classifies a stable expected delay as HIGH confidence", () => {
  const analysis = analyzeTimingDifferential({
    baseline: set([80, 84, 82, 81, 83]),
    negative: set([88, 86, 90, 87, 89]),
    positive: set([5080, 5090, 5100, 5070, 5110]),
    expectedDelayMs: 5000,
  });

  assert.equal(analysis.confirmed, true);
  assert.equal(analysis.confidence, "HIGH");
  assert.ok(analysis.deltaMs > 4900);
  assert.equal(analysis.thresholdMs, 4000);
});

test("timing differential remains LOW when positive and negative controls overlap", () => {
  const analysis = analyzeTimingDifferential({
    baseline: set([75, 80, 82, 77, 79]),
    negative: set([90, 94, 91, 89, 92]),
    positive: set([105, 98, 100, 102, 101]),
    expectedDelayMs: 5000,
  });

  assert.equal(analysis.confirmed, false);
  assert.equal(analysis.confidence, "LOW");
});

test("timing differential treats repeated positive-only timeouts as HIGH confidence", () => {
  const analysis = analyzeTimingDifferential({
    baseline: set([80, 82, 84]),
    negative: set([90, 92, 91]),
    positive: set([5010], 2),
    expectedDelayMs: 5000,
  });

  assert.equal(analysis.confirmed, true);
  assert.equal(analysis.confidence, "HIGH");
  assert.match(analysis.reason, /timeout/);
});

test("local timing lab is hard-limited to loopback targets", async () => {
  await assert.rejects(
    () =>
      runLocalTimingDifferentialLab({
        target: "https://example.com/dvwa/vulnerabilities/sqli/",
        phpSessionId: "local-session",
        fetchImpl: async () => {
          throw new Error("must not execute");
        },
      }),
    /restricted to localhost\/loopback/,
  );
});

test("local timing lab performs paired controls and renders structured evidence", async () => {
  const seen = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(String(input));
    const payload = url.searchParams.get("id");
    seen.push({
      payload,
      cookie: new Headers(init.headers).get("cookie"),
    });

    await new Promise((resolve) =>
      setTimeout(resolve, payload === "positive" ? 560 : 5),
    );
    return new Response("<title>SQL Injection</title>", {
      status: 200,
      headers: { "content-type": "text/html" },
    });
  };

  const result = await runLocalTimingDifferentialLab({
    target: "http://localhost/dvwa/vulnerabilities/sqli/",
    phpSessionId: "local-session",
    samples: 3,
    delayMs: 500,
    timeoutMs: 1500,
    experiments: [
      {
        name: "synthetic differential",
        negativePayload: "negative",
        positivePayload: "positive",
        expectedDelayMs: 500,
      },
    ],
    fetchImpl,
  });

  assert.equal(result.confirmed, 1);
  assert.equal(result.highConfidence, 1);
  assert.equal(result.experiments[0].analysis.confidence, "HIGH");
  assert.equal(seen.length, 9);
  assert.ok(
    seen.every(
      (entry) =>
        entry.cookie === "PHPSESSID=local-session; security=low",
    ),
  );

  const rendered = renderTimingLab(result);
  assert.match(rendered, /LOCAL TIMING DIFFERENTIAL LAB/);
  assert.match(rendered, /confidence=HIGH/);
});
