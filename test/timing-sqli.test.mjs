import test from "node:test";
import assert from "node:assert/strict";
import { renderTimingSqliLab, runLocalTimingSqliLab } from "../dist/index.js";

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
