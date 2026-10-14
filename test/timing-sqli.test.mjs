import test from "node:test";
import assert from "node:assert/strict";
import {
  renderTimingSqliLab,
  runLocalTimingSqliLab,
  toTimingSqliScanResult,
} from "../dist/index.js";
import { report } from "../dist/reporter.js";

function delayedFetch(delays) {
  return async (input, init = {}) => {
    const url = new URL(String(input));
    const payload = url.searchParams.get("id") ?? "";
    const delay = delays[payload] ?? 5;
    await new Promise((resolve, reject) => {
      const timer = setTimeout(resolve, delay);
      init.signal?.addEventListener(
        "abort",
        () => {
          clearTimeout(timer);
          reject(new DOMException("aborted", "AbortError"));
        },
        { once: true },
      );
    });
    return new Response("<h1>SQL Injection</h1>", {
      status: 200,
      headers: { "content-type": "text/html" },
    });
  };
}

test("timing SQLi lab confirms a repeatable positive/negative differential on loopback", async () => {
  const result = await runLocalTimingSqliLab(
    "http://127.0.0.1/dvwa/vulnerabilities/sqli/",
    {
      phpSessionId: "local-test-session",
      samples: 3,
      timeoutMs: 1000,
      baselinePayload: "BASE",
      experiments: [
        {
          name: "synthetic differential",
          positive: "POSITIVE",
          negative: "NEGATIVE",
          expectedDelayMs: 80,
        },
      ],
      responseMarker: "SQL Injection",
      fetchImpl: delayedFetch({
        BASE: 5,
        NEGATIVE: 5,
        POSITIVE: 100,
      }),
    },
  );

  assert.equal(result.confirmed, 1);
  assert.equal(result.highConfidence, 1);
  assert.equal(result.conclusion, "SUSPICIOUS");
  assert.equal(result.experiments[0].confirmed, true);
  assert.equal(result.experiments[0].confidence, "HIGH");
  assert.ok(result.experiments[0].deltaMs >= 70);

  const rendered = renderTimingSqliLab(result);
  assert.match(rendered, /REAPER LOCAL TIMING SQLi LAB/);
  assert.match(rendered, /confidence=HIGH/);
  assert.ok(!rendered.includes("local-test-session"));
});

test("timing SQLi lab rejects every non-loopback target before network access", async () => {
  let called = false;

  await assert.rejects(
    () =>
      runLocalTimingSqliLab("https://example.com/dvwa/vulnerabilities/sqli/", {
        phpSessionId: "local-test-session",
        samples: 3,
        experiments: [
          {
            name: "must never run",
            positive: "POSITIVE",
            negative: "NEGATIVE",
            expectedDelayMs: 80,
          },
        ],
        fetchImpl: async () => {
          called = true;
          return new Response("unexpected");
        },
      }),
    /restricted to localhost\/loopback/,
  );

  assert.equal(called, false);
});

test("timing SQLi lab treats repeated positive timeouts as high-confidence evidence", async () => {
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(String(input));
    const payload = url.searchParams.get("id") ?? "";
    if (payload === "POSITIVE") {
      return await new Promise((resolve, reject) => {
        const timer = setTimeout(
          () => resolve(new Response("<h1>SQL Injection</h1>")),
          500,
        );
        init.signal?.addEventListener(
          "abort",
          () => {
            clearTimeout(timer);
            reject(new DOMException("aborted", "AbortError"));
          },
          { once: true },
        );
      });
    }
    return new Response("<h1>SQL Injection</h1>", { status: 200 });
  };

  const result = await runLocalTimingSqliLab("http://localhost/dvwa/sqli/", {
    phpSessionId: "local-test-session",
    samples: 3,
    timeoutMs: 50,
    baselinePayload: "BASE",
    experiments: [
      {
        name: "timeout differential",
        positive: "POSITIVE",
        negative: "NEGATIVE",
        expectedDelayMs: 80,
      },
    ],
    responseMarker: "SQL Injection",
    fetchImpl,
  });

  assert.equal(result.experiments[0].confirmed, true);
  assert.equal(result.experiments[0].confidence, "HIGH");
  assert.match(result.experiments[0].reason, /exceeded timeout/);
});

test("timing lab rejects invalid experiments before issuing a request", async () => {
  let calls = 0;
  await assert.rejects(
    runLocalTimingSqliLab("http://localhost/dvwa/sqli/", {
      phpSessionId: "local",
      samples: 3,
      experiments: [
        {
          name: "invalid",
          positive: "P",
          negative: "N",
          expectedDelayMs: -1,
        },
      ],
      fetchImpl: async () => {
        calls++;
        return new Response("OK");
      },
    }),
    /definition is invalid/,
  );
  assert.equal(calls, 0);
});

test("timing lab cannot confirm repeated positive timeouts with broken negative controls", async () => {
  const fetchImpl = async (input, init) => {
    const payload = new URL(String(input)).searchParams.get("id");
    if (payload === "NEGATIVE") throw new Error("backend unavailable");
    if (payload === "POSITIVE")
      return new Promise((resolve, reject) => {
        init.signal.addEventListener(
          "abort",
          () => reject(new DOMException("aborted", "AbortError")),
          { once: true },
        );
      });
    return new Response("OK");
  };
  const result = await runLocalTimingSqliLab("http://localhost/dvwa/sqli/", {
    phpSessionId: "local",
    samples: 3,
    timeoutMs: 25,
    experiments: [
      {
        name: "unhealthy controls",
        positive: "POSITIVE",
        negative: "NEGATIVE",
        expectedDelayMs: 80,
      },
    ],
    fetchImpl,
  });
  assert.equal(result.confirmed, 0);
  assert.equal(result.experiments[0].confidence, "INCONCLUSIVE");
});

test("localhost timing lab pins outbound requests to a numeric loopback address", async () => {
  const hosts = [];
  const result = await runLocalTimingSqliLab("http://localhost/dvwa/sqli/", {
    phpSessionId: "local-session",
    samples: 3,
    timeoutMs: 1000,
    experiments: [
      {
        name: "control",
        positive: "POSITIVE",
        negative: "NEGATIVE",
        expectedDelayMs: 80,
      },
    ],
    fetchImpl: async (input) => {
      hosts.push(new URL(String(input)).hostname);
      return new Response("SQL Injection", { status: 200 });
    },
  });
  assert.equal(result.confirmed, 0);
  assert.equal(hosts.length, 9);
  assert.ok(hosts.every((hostname) => hostname === "127.0.0.1"));
});

test("timing lab resists a monotonic server-latency drift", async () => {
  let requests = 0;
  const fetchImpl = async () => {
    const delay = 10 + 20 * requests++;
    await new Promise((resolve) => setTimeout(resolve, delay));
    return new Response("SQL Injection", { status: 200 });
  };
  const result = await runLocalTimingSqliLab("http://127.0.0.1/dvwa/sqli/", {
    phpSessionId: "local-session",
    samples: 3,
    timeoutMs: 1000,
    experiments: [
      {
        name: "drift without injection",
        positive: "POSITIVE",
        negative: "NEGATIVE",
        expectedDelayMs: 70,
      },
    ],
    fetchImpl,
  });
  assert.equal(result.confirmed, 0);
  assert.equal(result.experiments[0].confidence, "LOW");
  assert.equal(requests, 9);
});

test("invalid session cookies are rejected before network activity", async () => {
  let requests = 0;
  await assert.rejects(
    runLocalTimingSqliLab("http://localhost/dvwa/sqli/", {
      phpSessionId: "abc; security=high",
      fetchImpl: async () => {
        requests++;
        return new Response("OK");
      },
    }),
    /valid bounded DVWA PHPSESSID/,
  );
  assert.equal(requests, 0);
});

test("non-200 application responses cannot be treated as timing evidence", async () => {
  const result = await runLocalTimingSqliLab("http://localhost/dvwa/sqli/", {
    phpSessionId: "local-session",
    samples: 3,
    timeoutMs: 1000,
    experiments: [
      {
        name: "unauthenticated",
        positive: "POSITIVE",
        negative: "NEGATIVE",
        expectedDelayMs: 80,
      },
    ],
    fetchImpl: async () => new Response("Unauthorized", { status: 401 }),
  });
  assert.equal(result.confirmed, 0);
  assert.equal(result.experiments[0].confidence, "INCONCLUSIVE");
});

test("timing evidence is exported as sanitized SARIF findings and Markdown", () => {
  const sample = { timesMs: [1, 2, 3], timeouts: 0, errors: 0, medianMs: 2, madMs: 1 };
  const result = {
    target: "http://127.0.0.1/dvwa/sqli/",
    samples: 3,
    timeoutMs: 1000,
    baseline: sample,
    experiments: [
      {
        name: "synthetic timing",
        expectedDelayMs: 80,
        negative: sample,
        positive: { ...sample, medianMs: 100 },
        confirmed: true,
        confidence: "HIGH",
        reason: "controlled differential",
        deltaMs: 98,
        thresholdMs: 64,
      },
    ],
    confirmed: 1,
    highConfidence: 1,
    conclusion: "SUSPICIOUS",
  };
  const scan = toTimingSqliScanResult(result);
  assert.equal(scan.findings.length, 1);
  assert.equal(scan.findings[0].ruleId, "REAPER-TIMING-001");
  assert.equal(scan.findings[0].severity, "MEDIUM");
  assert.notEqual(scan.findings[0].confidence, "CONFIRMED");
  const sarif = JSON.parse(report(scan, "sarif"));
  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.runs[0].results[0].ruleId, "REAPER-TIMING-001");
  assert.match(report(scan, "markdown"), /REAPER-TIMING-001/);
  assert.doesNotMatch(JSON.stringify(sarif), /PHPSESSID|REAPER_DVWA/);
});

test("timing lab rejects query strings and fragments before networking", async () => {
  let requested = false;
  await assert.rejects(
    runLocalTimingSqliLab("http://127.0.0.1/dvwa/sqli/?token=secret", {
      phpSessionId: "valid",
      fetchImpl: async () => {
        requested = true;
        return new Response("OK");
      },
    }),
    /query, or fragment/,
  );
  assert.equal(requested, false);
});
