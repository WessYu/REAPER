import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { once } from "node:events";
import {
  runTimingDifferential,
  validateConfig,
} from "../dist/index.js";

async function server(handler) {
  const instance = http.createServer(handler);
  instance.listen(0, "127.0.0.1");
  await once(instance, "listening");
  const address = instance.address();
  return {
    instance,
    origin: `http://127.0.0.1:${address.port}`,
  };
}

function config(overrides = {}) {
  return {
    timing: {
      authorization: {
        acknowledged: true,
        reference: "DVWA local laboratory",
      },
      samples: 3,
      timeoutMs: 1000,
      thresholdRatio: 0.7,
      minDeltaMs: 100,
      responseMustInclude: ["SQL Injection"],
      baseline: {
        path: "/lab",
        query: { id: "baseline" },
      },
      experiments: [
        {
          id: "paired-delay",
          title: "Paired local timing control",
          expectedDelayMs: 200,
          negative: {
            path: "/lab",
            query: { id: "negative" },
          },
          positive: {
            path: "/lab",
            query: { id: "positive" },
          },
        },
      ],
      ...overrides,
    },
  };
}

test("timing differential confirms a stable positive/negative delay on loopback", async () => {
  const { instance, origin } = await server(async (req, res) => {
    const url = new URL(req.url, origin);
    const id = url.searchParams.get("id");
    if (id === "positive") await new Promise((resolve) => setTimeout(resolve, 240));
    else await new Promise((resolve) => setTimeout(resolve, 15));
    res.statusCode = 200;
    res.end("<h1>SQL Injection</h1>");
  });

  try {
    const result = await runTimingDifferential(`${origin}/lab`, config());
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].ruleId, "REAPER-TIMING-001");
    assert.equal(result.findings[0].category, "Offensive Validation");
    assert.equal(result.timing.confirmedCount, 1);
    assert.equal(result.timing.highConfidenceCount, 1);
    assert.equal(result.timing.experiments[0].confirmed, true);
    assert.equal(result.timing.experiments[0].confidence, "HIGH");
    assert.ok(result.timing.experiments[0].deltaMs >= 180);
    assert.equal(result.metrics.sinks, 9);
  } finally {
    instance.close();
    await once(instance, "close");
  }
});

test("timing differential treats repeated positive timeouts as censored high-confidence evidence", async () => {
  const { instance, origin } = await server(async (req, res) => {
    const url = new URL(req.url, origin);
    if (url.searchParams.get("id") === "positive")
      await new Promise((resolve) => setTimeout(resolve, 300));
    else await new Promise((resolve) => setTimeout(resolve, 5));
    res.statusCode = 200;
    res.end("SQL Injection");
  });

  try {
    const value = config({ timeoutMs: 120 });
    const result = await runTimingDifferential(`${origin}/lab`, value);
    const experiment = result.timing.experiments[0];
    assert.equal(experiment.confirmed, true);
    assert.equal(experiment.confidence, "HIGH");
    assert.equal(experiment.positive.timeouts, 3);
    assert.equal(experiment.positive.durationsMs.length, 0);
    assert.equal(result.findings.length, 1);
  } finally {
    instance.close();
    await once(instance, "close");
  }
});

test("timing differential keeps an equal-speed pair unconfirmed", async () => {
  const { instance, origin } = await server(async (_req, res) => {
    await new Promise((resolve) => setTimeout(resolve, 15));
    res.statusCode = 200;
    res.end("SQL Injection");
  });

  try {
    const result = await runTimingDifferential(`${origin}/lab`, config());
    assert.equal(result.findings.length, 0);
    assert.equal(result.timing.confirmedCount, 0);
    assert.equal(result.timing.experiments[0].confirmed, false);
    assert.equal(result.timing.experiments[0].confidence, "LOW");
  } finally {
    instance.close();
    await once(instance, "close");
  }
});

test("timing differential forwards only explicitly named cookie environment values", async () => {
  process.env.DVWA_TEST_SESSION = "session-test";
  process.env.DVWA_TEST_SECURITY = "low";
  const seen = [];
  const { instance, origin } = await server((req, res) => {
    seen.push(req.headers.cookie ?? "");
    res.statusCode = 200;
    res.end("SQL Injection");
  });

  try {
    const value = config({
      cookieEnvs: {
        PHPSESSID: "DVWA_TEST_SESSION",
        security: "DVWA_TEST_SECURITY",
      },
      experiments: [
        {
          id: "cookie-control",
          title: "Cookie-backed local control",
          expectedDelayMs: 200,
          negative: { path: "/lab", query: { id: "negative" } },
          positive: { path: "/lab", query: { id: "negative" } },
        },
      ],
    });
    await runTimingDifferential(`${origin}/lab`, value);
    assert.ok(seen.length > 0);
    assert.ok(
      seen.every(
        (cookie) =>
          cookie.includes("PHPSESSID=session-test") &&
          cookie.includes("security=low"),
      ),
    );
  } finally {
    delete process.env.DVWA_TEST_SESSION;
    delete process.env.DVWA_TEST_SECURITY;
    instance.close();
    await once(instance, "close");
  }
});

test("timing differential rejects non-loopback targets before any request", async () => {
  await assert.rejects(
    runTimingDifferential("https://example.com/dvwa/", config()),
    /restricted to localhost\/loopback/,
  );
});

test("timing configuration is literal, bounded and explicitly authorized", () => {
  assert.doesNotThrow(() => validateConfig(config()));
  assert.throws(
    () =>
      validateConfig(
        config({
          samples: 10,
        }),
      ),
    /samples/,
  );
  assert.throws(
    () =>
      validateConfig({
        timing: {
          ...config().timing,
          authorization: {
            acknowledged: false,
            reference: "DVWA local laboratory",
          },
        },
      }),
    /acknowledged/,
  );
});
