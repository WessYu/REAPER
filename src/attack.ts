import { randomUUID } from "node:crypto";
import { lookup } from "node:dns/promises";
import { performance } from "node:perf_hooks";
import { finding } from "./findings.js";
import { validateAttackConfig } from "./attack-config.js";
import type {
  AttackConfig,
  AttackIdentity,
  AttackMatrix,
  AttackScenario,
  AttackStep,
  Config,
  ScanResult,
  Severity,
  VerifyJson,
} from "./model.js";

interface AttackContext {
  target: URL;
  config: AttackConfig;
  result: ScanResult;
  variables: Map<string, string>;
  requestCount: number;
  nextRequestAt: number;
  pacing: Promise<void>;
  consecutiveServerErrors: number;
  baselineAddresses: string[];
  signal?: AbortSignal;
}

function targetUrl(value: string): URL {
  const target = new URL(value);
  if (!["http:", "https:"].includes(target.protocol))
    throw new Error("Attack target must use http or https.");
  if (
    target.username ||
    target.password ||
    target.search ||
    target.hash ||
    target.pathname !== "/"
  )
    throw new Error("Attack target must be a bare HTTP(S) origin.");
  return target;
}

function authorizedTarget(target: URL, config: AttackConfig): boolean {
  return config.allowedTargets.some((entry) => {
    try {
      const allowed = new URL(entry);
      return allowed.origin === target.origin;
    } catch {
      return false;
    }
  });
}

function isIpLiteral(hostname: string): boolean {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname) || hostname.includes(":");
}

function isLoopbackAddress(address: string): boolean {
  const normalized = address.toLowerCase();
  if (normalized === "::1") return true;
  if (/^127(?:\.\d{1,3}){3}$/.test(normalized)) return true;
  const mapped = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  return mapped ? isLoopbackAddress(mapped[1]!) : false;
}

function isPrivateAddress(address: string): boolean {
  const normalized = address.toLowerCase();
  const mapped = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPrivateAddress(mapped[1]!);
  const ipv4 = normalized.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (ipv4) {
    const a = Number(ipv4[1]);
    const b = Number(ipv4[2]);
    return (
      a === 0 ||
      a === 10 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168)
    );
  }
  if (normalized === "::") return true;
  const first = Number.parseInt(normalized.split(":")[0] || "0", 16);
  return (first & 0xfe00) === 0xfc00 || (first & 0xffc0) === 0xfe80;
}

function assertNetworkScope(addresses: string[], config: AttackConfig): void {
  const privateNonLoopback = addresses.filter(
    (address) => isPrivateAddress(address) && !isLoopbackAddress(address),
  );
  if (privateNonLoopback.length && config.allowPrivateNetwork !== true)
    throw new Error(
      "Attack target resolves to a private/link-local network; set attack.allowPrivateNetwork=true only for explicitly authorized internal assessments.",
    );
}

async function resolvedAddresses(target: URL): Promise<string[]> {
  if (isIpLiteral(target.hostname)) return [target.hostname.toLowerCase()];
  const values = await lookup(target.hostname, { all: true, verbatim: true });
  return [
    ...new Set(values.map((value) => value.address.toLowerCase())),
  ].sort();
}

async function assertStableResolution(context: AttackContext): Promise<void> {
  const current = await resolvedAddresses(context.target);
  if (
    current.length !== context.baselineAddresses.length ||
    current.some((value, index) => value !== context.baselineAddresses[index])
  )
    throw new Error(
      "Target DNS resolution changed during the run; stopping to reduce DNS-rebinding risk.",
    );
}

function resultFor(target: URL): ScanResult {
  return {
    version: "0.2.0",
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

function interpolate(value: string, variables: Map<string, string>): string {
  return value.replace(
    /\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}/g,
    (_, name: string) => {
      const replacement = variables.get(name);
      if (replacement === undefined)
        throw new Error(`Missing captured variable ${name}.`);
      return replacement;
    },
  );
}

function requestPath(value: string, variables: Map<string, string>): string {
  return value.replace(
    /\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}/g,
    (_, name: string) => {
      const replacement = variables.get(name);
      if (replacement === undefined)
        throw new Error(`Missing captured variable ${name}.`);
      return encodeURIComponent(replacement);
    },
  );
}

function bodyValue(
  value: VerifyJson,
  variables: Map<string, string>,
): VerifyJson {
  if (typeof value === "string") {
    if (value.startsWith("$env:")) {
      const name = value.slice(5);
      const resolved = process.env[name];
      if (resolved === undefined)
        throw new Error(`Missing environment variable ${name}.`);
      return resolved;
    }
    return interpolate(value, variables);
  }
  if (Array.isArray(value))
    return value.map((entry) => bodyValue(entry, variables));
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [
        key,
        bodyValue(entry, variables),
      ]),
    );
  return value;
}

function identityToken(
  identity: AttackIdentity | undefined,
  variables: Map<string, string>,
): string | undefined {
  if (!identity) return undefined;
  if (identity.tokenEnv) {
    const value = process.env[identity.tokenEnv];
    if (!value)
      throw new Error(`Missing environment variable ${identity.tokenEnv}.`);
    return value;
  }
  if (identity.tokenVar) {
    const value = variables.get(identity.tokenVar);
    if (!value)
      throw new Error(`Missing captured variable ${identity.tokenVar}.`);
    return value;
  }
  return undefined;
}

async function pace(context: AttackContext): Promise<boolean> {
  let release!: () => void;
  const previous = context.pacing;
  context.pacing = new Promise<void>((resolve) => {
    release = resolve;
  });
  await previous;
  try {
    if (context.signal?.aborted) return false;
    const rate = context.config.rateLimitPerSecond ?? 3;
    const wait = Math.max(0, context.nextRequestAt - Date.now());
    if (wait) await new Promise((resolve) => setTimeout(resolve, wait));
    if (context.signal?.aborted) return false;
    context.nextRequestAt = Date.now() + Math.ceil(1000 / rate);
    return true;
  } finally {
    release();
  }
}

function consumeBudget(context: AttackContext): void {
  context.requestCount++;
  const max = context.config.maxRequests ?? 100;
  if (context.requestCount > max)
    throw new Error(`Attack request budget exceeded (${max}).`);
}

async function limitedJson(response: Response): Promise<unknown> {
  const maxBytes = 65536;
  const declared = Number(response.headers.get("content-length") ?? "0");
  if (declared > maxBytes)
    throw new Error("Response is too large for attack capture.");
  const text = await response.text();
  if (Buffer.byteLength(text, "utf8") > maxBytes)
    throw new Error("Response is too large for attack capture.");
  if (!text.trim()) return undefined;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new Error("Attack capture expected a JSON response.");
  }
}

function jsonPath(value: unknown, path: string): unknown {
  let current = value;
  for (const part of path.split(".").filter(Boolean)) {
    if (!current || typeof current !== "object" || !(part in current))
      return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}

function severity(scenario: AttackScenario): Severity {
  if (scenario.severity) return scenario.severity;
  if (scenario.dimension === "tenant" || scenario.dimension === "vertical")
    return "CRITICAL";
  return "HIGH";
}

function graphNode(
  result: ScanResult,
  id: string,
  kind: "route" | "query" | "resource" | "principal" | "finding",
  label: string,
): void {
  if (!result.graph.nodes.some((node) => node.id === id))
    result.graph.nodes.push({ id, kind, label });
}

function graphEdge(
  result: ScanResult,
  from: string,
  to: string,
  relation: "calls" | "accesses" | "acts-as" | "targets" | "confirms",
): void {
  if (
    !result.graph.edges.some(
      (edge) =>
        edge.from === from && edge.to === to && edge.relation === relation,
    )
  )
    result.graph.edges.push({ from, to, relation });
}

async function requestStep(
  context: AttackContext,
  scenario: AttackScenario,
  step: AttackStep,
  cleanup: boolean,
): Promise<void> {
  if (!(await pace(context))) throw new Error("Attack run cancelled.");
  consumeBudget(context);
  await assertStableResolution(context);

  const started = performance.now();
  const method = step.method ?? "GET";
  if (!["GET", "HEAD"].includes(method)) {
    if (context.config.allowMutations !== true)
      throw new Error(
        `Attack step ${step.name} uses ${method}; mutations are not enabled.`,
      );
    if (context.config.authorization.environment === "production")
      throw new Error("Mutating attack steps are blocked in production.");
  }
  const path = requestPath(step.path, context.variables);
  const url = new URL(path, context.target);
  if (url.origin !== context.target.origin)
    throw new Error("Attack request escaped the configured target origin.");

  const headers = new Headers({
    accept: "application/json, text/plain;q=0.5",
    "user-agent": "REAPER/0.2.0 authorized-attack-validation",
  });
  const identity = step.actor
    ? context.config.identities?.[step.actor]
    : undefined;
  const token = identityToken(identity, context.variables);
  if (token) headers.set("authorization", `Bearer ${token}`);

  let body: string | undefined;
  if (step.body !== undefined) {
    headers.set("content-type", "application/json");
    body = JSON.stringify(bodyValue(step.body, context.variables));
  }

  const controller = new AbortController();
  const timeout = setTimeout(
    () => controller.abort(),
    context.config.timeoutMs ?? 5000,
  );
  const signal = context.signal
    ? AbortSignal.any([controller.signal, context.signal])
    : controller.signal;

  let response: Response;
  try {
    response = await fetch(url, {
      method,
      headers,
      body,
      redirect: "manual",
      signal,
    });
  } finally {
    clearTimeout(timeout);
  }
  context.result.metrics.sinks++;

  if (response.status >= 500) context.consecutiveServerErrors++;
  else context.consecutiveServerErrors = 0;
  const serverErrorLimit = context.config.maxConsecutiveServerErrors ?? 3;
  if (context.consecutiveServerErrors >= serverErrorLimit) {
    await response.body?.cancel();
    throw new Error(
      `Circuit breaker opened after ${serverErrorLimit} consecutive server errors.`,
    );
  }

  const routeId = `route:attack:${method} ${step.path}`;
  graphNode(context.result, routeId, "route", `${method} ${step.path}`);
  if (step.actor) {
    const principalId = `principal:attack:${step.actor}`;
    graphNode(context.result, principalId, "principal", step.actor);
    graphEdge(context.result, principalId, routeId, "acts-as");
  }
  if (step.resource) {
    const resource = interpolate(step.resource, context.variables);
    const resourceId = `resource:attack:${resource}`;
    graphNode(context.result, resourceId, "resource", resource);
    graphEdge(context.result, routeId, resourceId, "targets");
  }

  const proof = step.expect?.jsonEquals;
  let parsed: unknown;
  if (
    (step.capture && Object.keys(step.capture).length) ||
    (proof && Object.keys(proof).length)
  ) {
    try {
      parsed = await limitedJson(response.clone());
    } catch (error) {
      if (proof && Object.keys(proof).length) {
        context.result.diagnostics.push({
          message: `Attack scenario ${scenario.id} step "${step.name}" could not validate JSON response proof: ${error instanceof Error ? error.message : "unknown error"}`,
        });
      } else {
        throw error;
      }
    }
  }

  if (step.capture && Object.keys(step.capture).length) {
    if (parsed === undefined)
      throw new Error("Attack capture expected a JSON response.");
    for (const [name, capturePath] of Object.entries(step.capture)) {
      const value = jsonPath(parsed, capturePath);
      if (!["string", "number", "boolean"].includes(typeof value))
        throw new Error(
          `Attack capture ${name} failed at JSON path ${capturePath}.`,
        );
      context.variables.set(name, String(value));
    }
  }

  const proofPaths = proof ? Object.keys(proof) : [];
  const proofMatched =
    proofPaths.length === 0 ||
    (parsed !== undefined &&
      proofPaths.every((proofPath) => {
        const expected = proof![proofPath];
        const resolvedExpected =
          typeof expected === "string"
            ? interpolate(expected, context.variables)
            : expected;
        return Object.is(jsonPath(parsed, proofPath), resolvedExpected);
      }));

  let outcome: "passed" | "confirmed" | "inconclusive" | "cleanup" = cleanup
    ? "cleanup"
    : "passed";
  const denied = step.expect?.deniedStatuses;
  const allowed = step.expect?.allowedStatuses;
  const confirmStatuses =
    step.expect?.confirmStatuses ??
    Array.from({ length: 100 }, (_, i) => 200 + i);
  if (denied && response.status >= 500) {
    outcome = "inconclusive";
    context.result.diagnostics.push({
      message: `Attack scenario ${scenario.id} step "${step.name}" returned HTTP ${response.status}; server errors cannot confirm an authorization bypass.`,
    });
  } else if (
    denied &&
    !denied.includes(response.status) &&
    !confirmStatuses.includes(response.status)
  ) {
    outcome = "inconclusive";
    context.result.diagnostics.push({
      message: `Attack scenario ${scenario.id} step "${step.name}" returned HTTP ${response.status}, which is outside both the denial policy and the confirmation-status policy; the result is inconclusive.`,
    });
  } else if (
    denied &&
    !denied.includes(response.status) &&
    proofPaths.length > 0 &&
    !proofMatched
  ) {
    outcome = "inconclusive";
    context.result.diagnostics.push({
      message: `Attack scenario ${scenario.id} step "${step.name}" violated the denial status policy but its configured JSON response proof did not match; the bypass remains unconfirmed.`,
    });
  } else if (denied && !denied.includes(response.status)) {
    const resource = step.resource
      ? interpolate(step.resource, context.variables)
      : undefined;
    const created = finding(
      {
        ruleId: "REAPER-ATTACK-001",
        title: "Configured authorization boundary was bypassed",
        description:
          "An authorized adversarial scenario reached a resource with an HTTP status outside the configured denial policy.",
        severity: severity(scenario),
        confidence: "CONFIRMED",
        category: "Offensive Validation",
        file: `runtime:${scenario.id}`,
        line: 1,
        column: 1,
        route: `${method} ${step.path}`,
        resource,
        evidence: [
          `Scenario: ${scenario.title}`,
          `Authorization reference: ${context.config.authorization.reference}`,
          `Dimension: ${scenario.dimension}`,
          `Actor: ${step.actor ?? "anonymous"}`,
          `Expected denial statuses: ${denied.join(", ")}`,
          `Confirmation statuses: ${confirmStatuses.join(", ")}`,
          `Observed HTTP status: ${response.status}`,
          ...(resource ? [`Known test resource: ${resource}`] : []),
          ...(proofPaths.length
            ? [`Response proof matched JSON paths: ${proofPaths.join(", ")}`]
            : []),
        ],
        dataFlow: [],
        recommendation:
          "Bind resource access to the authenticated principal/tenant at the application or database policy layer, then keep this scenario as a regression test.",
      },
      `${scenario.id}:${step.name}:${step.actor ?? "anonymous"}:${resource ?? ""}`,
    );
    context.result.findings.push(created);
    context.result.attack?.confirmed.push({
      scenarioId: scenario.id,
      findingId: created.id,
    });
    const findingId = `finding:${created.id}`;
    graphNode(context.result, findingId, "finding", created.title);
    graphEdge(context.result, routeId, findingId, "confirms");
    outcome = "confirmed";
  } else if (allowed && !allowed.includes(response.status)) {
    outcome = "inconclusive";
    context.result.diagnostics.push({
      message: `Attack scenario ${scenario.id} step "${step.name}" expected an allowed status (${allowed.join(", ")}) but received ${response.status}.`,
    });
  } else if (allowed && proofPaths.length > 0 && !proofMatched) {
    outcome = "inconclusive";
    context.result.diagnostics.push({
      message: `Attack scenario ${scenario.id} step "${step.name}" matched its allowed status policy but its configured JSON response proof did not match.`,
    });
  }

  await response.body?.cancel();
  context.result.attack?.audit.push({
    scenarioId: scenario.id,
    step: step.name,
    actor: step.actor,
    method,
    path: step.path,
    status: response.status,
    durationMs: Math.round(performance.now() - started),
    outcome,
  });
}

async function runMatrix(
  context: AttackContext,
  matrix: AttackMatrix,
): Promise<void> {
  const previousResourceId = context.variables.get("RESOURCE_ID");
  const previousResourceOwner = context.variables.get("RESOURCE_OWNER");
  const previousActor = context.variables.get("ACTOR");
  try {
    for (const actor of matrix.actors) {
      context.variables.set("ACTOR", actor);
      for (const resource of matrix.resources) {
        if (actor === resource.owner) continue;
        const resourceId = interpolate(resource.id, context.variables);
        context.variables.set("RESOURCE_ID", resourceId);
        context.variables.set("RESOURCE_OWNER", resource.owner);
        const scenario: AttackScenario = {
          id: `${matrix.id}.${actor}.vs.${resource.owner}`,
          title: matrix.title,
          dimension: matrix.dimension,
          severity: matrix.severity,
          steps: [],
        };
        const step: AttackStep = {
          name: `${actor} -> ${resource.label ?? resourceId}`,
          path: matrix.path,
          method: matrix.method ?? "GET",
          actor,
          resource:
            resource.label ??
            `${matrix.id}:${resourceId}:owner:${resource.owner}`,
          expect: {
            deniedStatuses: matrix.deniedStatuses,
            confirmStatuses: matrix.confirmStatuses,
            jsonEquals: matrix.jsonEquals,
          },
        };
        try {
          await requestStep(context, scenario, step, false);
        } catch (error) {
          context.result.diagnostics.push({
            message: `Attack matrix ${matrix.id} stopped at ${actor} -> ${resource.owner}: ${error instanceof Error ? error.message : "unknown error"}`,
          });
          context.result.attack?.audit.push({
            scenarioId: scenario.id,
            step: step.name,
            actor,
            method: step.method ?? "GET",
            path: step.path,
            durationMs: 0,
            outcome: "error",
          });
          if (context.consecutiveServerErrors > 0 || context.signal?.aborted)
            return;
        }
      }
    }
  } finally {
    if (previousResourceId === undefined)
      context.variables.delete("RESOURCE_ID");
    else context.variables.set("RESOURCE_ID", previousResourceId);
    if (previousResourceOwner === undefined)
      context.variables.delete("RESOURCE_OWNER");
    else context.variables.set("RESOURCE_OWNER", previousResourceOwner);
    if (previousActor === undefined) context.variables.delete("ACTOR");
    else context.variables.set("ACTOR", previousActor);
  }
}

export async function runAttack(
  target: string,
  config: Config,
  options: { signal?: AbortSignal } = {},
): Promise<ScanResult> {
  if (!config.attack)
    throw new Error("Attack mode requires an attack configuration.");
  const attack = validateAttackConfig(config.attack);
  const parsed = targetUrl(target);
  if (!authorizedTarget(parsed, attack))
    throw new Error("Attack target is blocked by the exact-origin allowlist.");

  const started = performance.now();
  const startedAt = new Date().toISOString();
  const result = resultFor(parsed);
  result.attack = {
    runId: randomUUID(),
    target: parsed.origin,
    authorizationReference: attack.authorization.reference,
    authorizationExpiresAt: attack.authorization.expiresAt,
    environment: attack.authorization.environment,
    startedAt,
    completedAt: startedAt,
    requests: 0,
    cleanupFailures: 0,
    confirmed: [],
    audit: [],
  };
  const baselineAddresses = await resolvedAddresses(parsed);
  assertNetworkScope(baselineAddresses, attack);
  const context: AttackContext = {
    target: parsed,
    config: attack,
    result,
    variables: new Map<string, string>(),
    requestCount: 0,
    nextRequestAt: 0,
    pacing: Promise.resolve(),
    consecutiveServerErrors: 0,
    baselineAddresses,
    signal: options.signal,
  };

  for (const scenario of attack.scenarios ?? []) {
    let scenarioFailed = false;
    let currentStep: AttackStep | undefined;
    try {
      for (const step of scenario.steps) {
        currentStep = step;
        await requestStep(context, scenario, step, false);
      }
      currentStep = undefined;
    } catch (error) {
      scenarioFailed = true;
      result.diagnostics.push({
        message: `Attack scenario ${scenario.id} stopped: ${error instanceof Error ? error.message : "unknown error"}`,
      });
      result.attack.audit.push({
        scenarioId: scenario.id,
        step: currentStep?.name ?? "scenario",
        actor: currentStep?.actor,
        method: currentStep?.method ?? "GET",
        path: currentStep?.path ?? "",
        durationMs: 0,
        outcome: "error",
      });
    } finally {
      const cleanup = [...(scenario.cleanup ?? [])].reverse();
      for (const step of cleanup)
        try {
          await requestStep(context, scenario, step, true);
        } catch (error) {
          result.attack.cleanupFailures++;
          result.attack.audit.push({
            scenarioId: scenario.id,
            step: step.name,
            actor: step.actor,
            method: step.method ?? "GET",
            path: step.path,
            durationMs: 0,
            outcome: "cleanup-error",
          });
          result.diagnostics.push({
            message: `Attack scenario ${scenario.id} cleanup failed: ${error instanceof Error ? error.message : "unknown error"}`,
          });
        }
    }
    if (context.signal?.aborted) {
      result.diagnostics.push({ message: "Attack run cancelled." });
      break;
    }
    if (scenarioFailed && context.consecutiveServerErrors > 0) break;
  }

  if (!context.signal?.aborted && context.consecutiveServerErrors === 0)
    for (const matrix of attack.matrices ?? []) {
      await runMatrix(context, matrix);
      if (context.signal?.aborted || context.consecutiveServerErrors > 0) break;
    }

  result.metrics.durationMs = Math.round(performance.now() - started);
  result.metrics.memoryBytes = process.memoryUsage().rss;
  result.attack.requests = context.requestCount;
  result.attack.completedAt = new Date().toISOString();
  return result;
}
