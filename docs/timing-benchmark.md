# Deterministic timing-classification benchmark

Run the virtual simulation from a repository build:

```sh
npm run benchmark:timing > timing-benchmark.json
```

The simulator calls the **same pure classifier used by the local timing lab**. Its observations contain the control role, order, latency, status, response length, body digest and marker validation. Every result carries a versioned reason code (`TIMING_REASON_SCHEMA_VERSION = 1`).

The classifier intentionally treats observations as an unordered multiset. Collection-order diagnostics (such as drift) are **separate**, and never change the classification. A repeated seed produces the same virtual outputs.

## Scenarios and names

Each scenario records its distribution, delay `D` in milliseconds, sample count `N`, regime and scale. When naming persisted files, use:

```text
timing_abs_D1000_N5_sigma50_gaussian_seed20261014.json
timing_prop_D1000_N5_sigma0.1_gaussian_seed20261014.json
```

- `abs`: jitter scale is in milliseconds and remains fixed as `D` changes.
- `prop`: jitter scale is a fraction of `D`; `sigma=0.1` means `sigmaMs = 0.1D`.
- Distributions: uniform, Gaussian, log-normal, bimodal, variance-growing drift and correlated bursts.
- `REAPER_TIMING_TRIALS` sets the number of trials **per class per scenario** (default 200; maximum 100,000); `REAPER_TIMING_SEED` sets the deterministic PRNG seed.

The virtual model starts with 40 ms of nominal latency, adds synthetic jitter, then optionally adds the ground-truth delay to the positive control. Extremely short samples are clamped; over-timeout samples are censored. It does **not** model actual TCP handshakes, connection reuse, OS scheduling, GC, DNS, response streams or server-side execution. Correlated bursts and drift explicitly break the i.i.d. assumption.

## Outcome metrics

`fprComposite` measures *false confirmations / all non-vulnerable trials* and includes inconclusive trials in the denominator. Its 95% Wilson interval includes sampling uncertainty, **not** simulator-model error.

`fprAmongDecisions` measures *false confirmations / non-vulnerable trials that reached a decision*. It is `null` when there are no decisions.

`decisionCoverage` and `inconclusiveRate` must accompany either FPR. A detector that always refuses to decide would have a misleading composite FPR of zero.

`tprComposite` is true confirmations per ground-truth vulnerable trial. `baselineAlarmRate` is an independent diagnostic: it measures how often the baseline median exceeds `0.8D`, **not** the detector's FPR.

`simulatedCostMsPerTrial` is the sum of virtual request latencies (including timeout censoring) averaged per trial. `simulatedCostMsPerDecision` averages the accumulated virtual latencies only among trials that reach a decision. Neither is measured wall-clock time.

The `CONTENT_EFFECT_UNOBSERVED` diagnostic is a **stratum**, not an exclusion rule. In blind timing injection, identical response bodies can accompany genuine vulnerabilities. Report performance separately by content-effect stratum when the corpus supports it, but retain all eligible labeled targets in the principal metric unless a predeclared independent eligibility rule excludes them.

## Real-world validation boundary

The existing `test/timing-network.test.mjs` uses a real loopback HTTP server and no fake fetch; its timing is subject to scheduler and transport variability. A virtual-versus-real comparison must declare tolerances and model differences **before** looking at results. Do not report virtual FPR or TPR as observed product accuracy.

This benchmark is a regression and design instrument, not an authorization to probe third-party hosts and not a commercial certification.
