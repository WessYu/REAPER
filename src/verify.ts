import { performance } from "node:perf_hooks";
import { finding } from "./findings.js";
import type { Config, ScanResult, VerifyAssertion } from "./model.js";

function targetUrl(value: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("Verification target must be an absolute URL.");
  }
  if (!["http:", "https:"].includes(parsed.protocol))
    throw new Error("Verification target must use http or https.");
  if (parsed.username || parsed.password)
    throw new Error("Verification target must not contain URL credentials.");
  parsed.hash = "";
  return parsed;
}

function isLoopback(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  return (
    normalized === "localhost" ||
    normalized === "127.0.0.1" ||
    normalized === "::1"
  );
}

function authorizedTarget(target: URL, config: Config): boolean {
  if (isLoopback(target.hostname)) return true;
  const allowed = config.verify?.allowedTargets ?? [];
  return allowed.some((entry) => {
    try {
      return new URL(entry).origin === target.origin;
    } catch {
      return false;
    }
  });
}

function runtimeResult(target: URL): ScanResult {
  return {
    version: "0.1.0",
    root: target.origin,
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

function severity(assertion: VerifyAssertion): "CRITICAL" | "HIGH" {
  return assertion.dimension === "tenant" ? "CRITICAL" : "HIGH";
}

export async function verify(target: string, config: Config): Promise<ScanResult> {
  const start = performance.now();
  const parsed = targetUrl(target);
  if (!config.verify)
    throw new Error("Verification configuration is required.");
  if (!authorizedTarget(parsed, config))
    throw new Error(
      "Remote verification target is blocked. Add its exact origin to verify.allowedTargets.",
    );

  const assertions = config.verify.assertions;
  const maxRequests = config.verify.maxRequests ?? 100;
  if (assertions.length > maxRequests)
    throw new Error(
      `Verification requires ${assertions.length} requests but maxRequests is ${maxRequests}.`,
    );
  const concurrency = Math.min(config.verify.concurrency ?? 2, 8);
  const timeoutMs = config.verify.timeoutMs ?? 5000;
  const result = runtimeResult(parsed);
  let cursor = 0;

  async function execute(assertion: VerifyAssertion): Promise<void> {
    const requestUrl = new URL(assertion.path, parsed);
    if (requestUrl.origin !== parsed.origin)
      throw new Error("Verification assertion escaped the target origin.");
    const method = assertion.method ?? "GET";
    const headers = new Headers({
      accept: "application/json, text/plain;q=0.5",
      "user-agent": "REAPER/0.1.0 authorized-verification",
    });
    if (assertion.authEnv) {
      const token = process.env[assertion.authEnv];
      if (!token) {
        result.diagnostics.push({
          message: `Verification assertion "${assertion.name}" requires environment variable ${assertion.authEnv}.`,
        });
        return;
      }
      headers.set("authorization", `Bearer ${token}`);
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(requestUrl, {
        method,
        headers,
        redirect: "manual",
        signal: controller.signal,
      });
      await response.body?.cancel();
      result.metrics.sinks++;
      if (response.status === assertion.expectStatus) return;

      const route = `${method} ${requestUrl.pathname}`;
      const loc = {
        file: `runtime/${requestUrl.hostname}`,
        line: 1,
        column: 1,
      };
      result.findings.push(
        finding(
          {
            ...loc,
            ruleId: "REAPER-VERIFY-001",
            title: "Configured authorization assertion failed",
            description:
              `Assertion "${assertion.name}" expected HTTP ${assertion.expectStatus} but received ${response.status}.`,
            severity: severity(assertion),
            confidence: "CONFIRMED",
            category: "Runtime Verification",
            cwe: assertion.dimension === "tenant" ? 639 : 862,
            route,
            resource: assertion.path,
            evidence: [
              `Assertion: ${assertion.name}`,
              `Expected status: ${assertion.expectStatus}`,
              `Observed status: ${response.status}`,
              assertion.authEnv
                ? `Authentication token supplied from environment variable ${assertion.authEnv}.`
                : "Request was sent without an Authorization header.",
            ],
            dataFlow: [],
            recommendation:
              "Review the target route's authentication, ownership/tenant checks and database policy path. Re-run this assertion after remediation.",
          },
          `verify:${parsed.origin}:${method}:${assertion.path}:${assertion.name}`,
        ),
      );
    } catch (error) {
      const reason =
        error instanceof Error && error.name === "AbortError"
          ? `timed out after ${timeoutMs}ms`
          : "failed before an HTTP status was received";
      result.diagnostics.push({
        message: `Verification assertion "${assertion.name}" ${reason}.`,
      });
    } finally {
      clearTimeout(timeout);
    }
  }

  async function worker(): Promise<void> {
    for (;;) {
      const index = cursor++;
      const assertion = assertions[index];
      if (!assertion) return;
      await execute(assertion);
    }
  }

  await Promise.all(
    Array.from({ length: Math.min(concurrency, assertions.length) }, () =>
      worker(),
    ),
  );
  result.findings.sort((a, b) => a.id.localeCompare(b.id));
  result.metrics.durationMs = Math.round(performance.now() - start);
  result.metrics.memoryBytes = process.memoryUsage().rss;
  return result;
}
