import { createHash } from "node:crypto";
import { performance } from "node:perf_hooks";
import { finding } from "./findings.js";
import { validateAttackConfig } from "./attack-config.js";
import type {
  AttackAuditEvent,
  AttackConfig,
  AttackIdentity,
  AttackScenario,
  AttackScenarioResult,
  AttackStep,
  Config,
  Finding,
  GraphEdge,
  GraphNode,
  ScanResult,
  VerifyJson,
} from "./model.js";

interface AttackContext {
  target: URL;
  config: AttackConfig;
  result: ScanResult;
  variables: Map<string, string>;
  signal?: AbortSignal;
  requestCount: number;
  serverErrors: number;
  nextRequestAt: number;
  sequence: number;
}

function parseTarget(value: string): URL {
  let target: URL;
  try {
    target = new URL(value);
  } catch {
    throw new Error("Attack target must be an absolute URL.");
  }
  if (!["http:", "https:"].includes(target.protocol))
    throw new Error("Attack target must use http or https.");
  if (target.username || target.password)
    throw new Error("Attack target must not contain URL credentials.");
  target.hash = "";
  target.pathname = "/";
  target.search = "";
  return target;
}

function loopback(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  return (
    normalized === "localhost" ||
    normalized === "127.0.0.1" ||
    normalized === "::1"
  );
}

function targetAllowed(target: URL, config: AttackConfig): boolean {
  if (loopback(target.hostname)) return true;
  return (config.scope.allowedTargets ?? []).some((entry) => {
    try {
      return new URL(entry).origin === target.origin;
    } catch {
      return false;
    }
  });
}

function assertScopeFresh(config: AttackConfig): void {
  if (
    config.scope.expiresAt &&
    Date.parse(config.scope.expiresAt) <= Date.now()
  )
    throw new Error("Attack scope authorization has expired.");
}

function pathAllowed(pathname: string, config: AttackConfig): boolean {
  const prefixes = config.scope.pathPrefixes ?? [];
  if (!prefixes.length) return true;
  return prefixes.some((prefix) => {
    const normalized = prefix.endsWith("/") ? prefix : prefix + "/";
    return pathname === prefix || pathname.startsWith(normalized);
  });
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

function interpolatePath(
  value: string,
  variables: Map<string, string>,
): string {
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

function interpolateBody(
  value: VerifyJson,
  variables: Map<string, string>,
): VerifyJson {
  if (typeof value === "string") {
    if (value.startsWith("$env:")) {
      const name = value.slice("$env:".length);
      const resolved = process.env[name];
      if (resolved === undefined)
        throw new Error(`Missing environment variable ${name}.`);
      return resolved;
    }
    return interpolate(value, variables);
  }
  if (Array.isArray(value))
    return value.map((item) => interpolateBody(item, variables));
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [
        key,
        interpolateBody(item, variables),
      ]),
    );
  return value;
}

function jsonPath(value: unknown, path: string): unknown {
  let current = value;
  for (const part of path.split(".")) {
    if (!part) continue;
    if (Array.isArray(current) && /^\d+$/.test(part))
      current = current[Number(part)];
    else if (current && typeof current === "object")
      current = (current as Record<string, unknown>)[part];
    else return undefined;
  }
  return current;
}

async function boundedJson(
  response: Response,
  maxBytes = 65536,
): Promise<unknown> {
  const declared = Number(response.headers.get("content-length") ?? "0");
  if (Number.isFinite(declared) && declared > maxBytes) {
    await response.body?.cancel();
    throw new Error("Response body exceeds capture limit.");
  }
  if (!response.body) return undefined;
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error("Response body exceeds capture limit.");
    }
    chunks.push(value);
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  const text = new TextDecoder().decode(merged);
  if (!text.trim()) return undefined;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

function tokenFor(
  identity: AttackIdentity | undefined,
  variables: Map<string, string>,
): string | undefined {
  if (!identity) return undefined;
  if (identity.authEnv) {
    const token = process.env[identity.authEnv];
    if (!token)
      throw new Error(
        `Missing environment variable ${identity.authEnv} for attack identity.`,
      );
    return token;
  }
  if (identity.authVar) {
    const token = variables.get(identity.authVar);
    if (!token)
      throw new Error(
        `Missing captured variable ${identity.authVar} for attack identity.`,
      );
    return token;
  }
  return undefined;
}

function cookieFor(
  identity: AttackIdentity | undefined,
  variables: Map<string, string>,
): string | undefined {
  if (!identity) return undefined;
  if (identity.cookieEnv) {
    const cookie = process.env[identity.cookieEnv];
    if (!cookie)
      throw new Error(
        `Missing environment variable ${identity.cookieEnv} for attack identity.`,
      );
    return cookie;
  }
  if (identity.cookieVar) {
    const cookie = variables.get(identity.cookieVar);
    if (!cookie)
      throw new Error(
        `Missing captured variable ${identity.cookieVar} for attack identity.`,
      );
    return cookie;
  }
  return undefined;
}

function headerValue(
  value: string,
  variables: Map<string, string>,
): string {
  if (value.startsWith("$env:")) {
    const name = value.slice("$env:".length);
    const resolved = process.env[name];
    if (resolved === undefined)
      throw new Error(`Missing environment variable ${name}.`);
    return resolved;
  }
  return interpolate(value, variables);
}

async function pace(context: AttackContext): Promise<void> {
  const rate = context.config.rateLimitPerSecond ?? 5;
  const wait = Math.max(0, context.nextRequestAt - Date.now());
  if (wait) await new Promise((resolve) => setTimeout(resolve, wait));
  context.nextRequestAt = Date.now() + Math.ceil(1000 / rate);
}

function consumeBudget(context: AttackContext): void {
  context.requestCount++;
  const maximum = context.config.maxRequests ?? 100;
  if (context.requestCount > maximum)
    throw new Error(`Attack request budget exceeded (${maximum}).`);
}

function checkCircuitBreaker(context: AttackContext): void {
  const maximum = context.config.maxServerErrors ?? 3;
  if (context.serverErrors >= maximum)
    throw new Error(
      `Attack circuit breaker opened after ${context.serverErrors} server errors.`,
    );
}

async function executeRequest(
  context: AttackContext,
  scenario: AttackScenario,
  step: AttackStep,
  phase: AttackAuditEvent["phase"],
): Promise<Response | undefined> {
  if (context.signal?.aborted) return undefined;
  checkCircuitBreaker(context);
  const method = step.method ?? "GET";
  if (
    ["POST", "PUT", "PATCH", "DELETE"].includes(method) &&
    context.config.allowMutations !== true
  )
    throw new Error("Mutating attack requests require allowMutations=true.");

  await pace(context);
  if (context.signal?.aborted) return undefined;
  consumeBudget(context);

  const renderedPath = interpolatePath(step.path, context.variables);
  const url = new URL(renderedPath, context.target);
  if (url.origin !== context.target.origin)
    throw new Error("Attack request escaped the authorized target origin.");
  if (!pathAllowed(url.pathname, context.config))
    throw new Error(
      `Attack request path is outside configured scope: ${step.path}`,
    );

  const identityName =
    step.identity ??
    (phase === "attack" ? scenario.attackerIdentity : undefined);
  const identity = identityName
    ? context.config.identities[identityName]
    : undefined;
  const token = tokenFor(identity, context.variables);
  const cookie = cookieFor(identity, context.variables);
  const headers = new Headers({
    accept: "application/json, text/plain;q=0.5",
    "user-agent": "REAPER/0.2.0 authorized-active-security",
  });
  if (token) headers.set("authorization", `Bearer ${token}`);
  if (cookie) headers.set("cookie", cookie);
  for (const [name, value] of Object.entries(step.headers ?? {}))
    headers.set(name, headerValue(value, context.variables));

  let body: string | undefined;
  if (step.body !== undefined) {
    headers.set("content-type", "application/json");
    body = JSON.stringify(interpolateBody(step.body, context.variables));
  }

  const controller = new AbortController();
  const timeoutMs = context.config.timeoutMs ?? 5000;
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  const signal = context.signal
    ? AbortSignal.any([controller.signal, context.signal])
    : controller.signal;
  const started = performance.now();
  let response: Response | undefined;
  try {
    response = await fetch(url, {
      method,
      headers,
      body,
      redirect: "manual",
      signal,
    });
    if (response.status >= 500) context.serverErrors++;
    return response;
  } finally {
    clearTimeout(timeout);
    context.result.attack!.audit.push({
      sequence: ++context.sequence,
      scenario: scenario.name,
      step: step.name,
      identity: identityName,
      method,
      path: step.path,
      status: response?.status,
      durationMs: Math.round(performance.now() - started),
      phase,
    });
  }
}

function sourceFindingFor(
  scenario: AttackScenario,
  sourceReport: ScanResult | undefined,
): Finding | undefined {
  if (!sourceReport) return undefined;
  if (scenario.sourceFindingId)
    return sourceReport.findings.find(
      (item) => item.id === scenario.sourceFindingId,
    );
  const candidates = sourceReport.findings.filter((item) => {
    if (item.status === "suppressed") return false;
    if (
      scenario.kind === "bola" &&
      item.ruleId !== "REAPER-AUTH-001"
    )
      return false;
    if (
      scenario.kind === "tenant" &&
      item.ruleId !== "REAPER-TENANT-001"
    )
      return false;
    if (
      scenario.kind === "privilege" &&
      item.category !== "Privileges"
    )
      return false;
    return true;
  });
  const route = `${scenario.attack.method ?? "GET"} ${scenario.attack.path}`;
  return (
    candidates.find(
      (item) =>
        item.route === route &&
        (!scenario.resource || item.resource === scenario.resource),
    ) ??
    candidates.find(
      (item) =>
        scenario.resource !== undefined &&
        item.resource === scenario.resource,
    ) ??
    candidates.find((item) => item.route === route)
  );
}

function addGraph(
  context: AttackContext,
  scenario: AttackScenario,
  findingId?: string,
  sourceFinding?: Finding,
): void {
  const principalId = `principal:${scenario.attackerIdentity}`;
  const requestId = `request:${scenario.name}`;
  const resourceId = `resource:${scenario.resource ?? scenario.attack.path}`;
  const nodes: GraphNode[] = [
    {
      id: principalId,
      kind: "principal" as const,
      label: scenario.attackerIdentity,
    },
    {
      id: requestId,
      kind: "request" as const,
      label: `${scenario.attack.method ?? "GET"} ${scenario.attack.path}`,
    },
    {
      id: resourceId,
      kind: "resource" as const,
      label: scenario.resource ?? scenario.attack.path,
    },
  ];
  if (findingId)
    nodes.push({
      id: `finding:${findingId}`,
      kind: "finding" as const,
      label: findingId,
    });
  if (sourceFinding)
    nodes.push({
      id: `finding:${sourceFinding.id}`,
      kind: "finding" as const,
      label: `${sourceFinding.ruleId} ${sourceFinding.file}:${sourceFinding.line}`,
    });
  for (const node of nodes)
    if (!context.result.graph.nodes.some((item) => item.id === node.id))
      context.result.graph.nodes.push(node);
  const edges: GraphEdge[] = [
    { from: principalId, to: requestId, relation: "tests" as const },
    { from: requestId, to: resourceId, relation: "accesses" as const },
  ];
  if (findingId)
    edges.push({
      from: requestId,
      to: `finding:${findingId}`,
      relation: "observed" as const,
    });
  if (sourceFinding)
    edges.push({
      from: `finding:${sourceFinding.id}`,
      to: requestId,
      relation: "correlates" as const,
    });
  for (const edge of edges)
    if (
      !context.result.graph.edges.some(
        (item) =>
          item.from === edge.from &&
          item.to === edge.to &&
          item.relation === edge.relation,
      )
    )
      context.result.graph.edges.push(edge);
}

function activeFinding(
  context: AttackContext,
  scenario: AttackScenario,
  status: number,
  sourceReport: ScanResult | undefined,
): Finding {
  const attacker = context.config.identities[scenario.attackerIdentity];
  const owner = scenario.ownerIdentity
    ? context.config.identities[scenario.ownerIdentity]
    : undefined;
  const ruleIds: Record<AttackScenario["kind"], string> = {
    bola: "REAPER-ATTACK-001",
    tenant: "REAPER-ATTACK-002",
    privilege: "REAPER-ATTACK-003",
    authorization: "REAPER-ATTACK-004",
    session: "REAPER-ATTACK-005",
    cors: "REAPER-ATTACK-006",
    csrf: "REAPER-ATTACK-007",
    business: "REAPER-ATTACK-008",
  };
  const titles: Record<AttackScenario["kind"], string> = {
    bola: "Cross-user object access confirmed",
    tenant: "Cross-tenant data access confirmed",
    privilege: "Privilege boundary violation confirmed",
    authorization: "Authorization expectation violated",
    session: "Session security expectation violated",
    cors: "Cross-origin policy expectation violated",
    csrf: "Cross-site request protection expectation violated",
    business: "Business security invariant violated",
  };
  const ruleId = ruleIds[scenario.kind];
  const title = titles[scenario.kind];
  const severity =
    scenario.kind === "tenant" || scenario.kind === "privilege"
      ? "CRITICAL"
      : "HIGH";
  const source = scenario.sourceFindingId
    ? sourceReport?.findings.find(
        (item) => item.id === scenario.sourceFindingId,
      )
    : undefined;
  const evidence = [
    `Scenario: ${scenario.name}`,
    `Attacker identity: ${scenario.attackerIdentity}${attacker?.role ? ` (role ${attacker.role})` : ""}`,
    ...(scenario.ownerIdentity
      ? [
          `Owner identity: ${scenario.ownerIdentity}${owner?.role ? ` (role ${owner.role})` : ""}`,
        ]
      : []),
    ...(attacker?.tenant ? [`Attacker tenant: ${attacker.tenant}`] : []),
    ...(owner?.tenant ? [`Owner tenant: ${owner.tenant}`] : []),
    `Observed HTTP status: ${status}`,
    `Expected statuses: ${(
      scenario.expect?.statuses ??
      scenario.denyStatuses ??
      (scenario.attack.expectStatus !== undefined
        ? [scenario.attack.expectStatus]
        : [401, 403, 404])
    ).join(", ")}`,
    ...Object.entries(scenario.expect?.headers ?? {}).map(
      ([name, expected]) =>
        `Expected response header ${name}: ${expected}`,
    ),
    ...(scenario.expect?.absentHeaders ?? []).map(
      (name) => `Expected response header absent: ${name}`,
    ),
    ...(source
      ? [
          `Correlated static finding: ${source.id} at ${source.file}:${source.line}`,
        ]
      : []),
  ];
  return finding(
    {
      ruleId,
      title,
      description:
        "An explicitly authorized active scenario observed access outside the declared identity or authorization boundary.",
      severity,
      confidence: "CONFIRMED",
      category: "Active Security",
      cwe:
        scenario.kind === "bola"
          ? 639
          : scenario.kind === "privilege"
            ? 269
            : 862,
      file: source?.file ?? "runtime",
      line: source?.line ?? 1,
      column: source?.column ?? 1,
      route: `${scenario.attack.method ?? "GET"} ${scenario.attack.path}`,
      resource: scenario.resource,
      evidence,
      dataFlow: source?.dataFlow ?? [],
      recommendation:
        scenario.kind === "tenant"
          ? "Bind data access to the authenticated tenant at the application and/or database policy layer, then retain this scenario as a regression gate."
          : scenario.kind === "bola"
            ? "Bind object lookup to the authenticated principal or enforce equivalent row-level authorization, then retain this scenario as a regression gate."
            : "Enforce the declared authorization boundary before data access and retain this scenario as a regression gate.",
    },
    `${scenario.kind}:${scenario.name}:${scenario.attack.path}`,
  );
}

async function runStep(
  context: AttackContext,
  scenario: AttackScenario,
  step: AttackStep,
  phase: "setup" | "cleanup",
): Promise<boolean> {
  try {
    const response = await executeRequest(context, scenario, step, phase);
    if (!response) return false;
    context.result.metrics.sinks++;
    const needsBody =
      step.capture !== undefined && Object.keys(step.capture).length > 0;
    const captured = needsBody
      ? await boundedJson(response)
      : (await response.body?.cancel(), undefined);
    if (
      step.expectStatus !== undefined &&
      response.status !== step.expectStatus
    ) {
      context.result.diagnostics.push({
        message: `${phase} step "${step.name}" expected HTTP ${step.expectStatus} but received ${response.status}.`,
      });
      return false;
    }
    for (const [name, jsonPathExpression] of Object.entries(
      step.capture ?? {},
    )) {
      const value = jsonPath(captured, jsonPathExpression);
      if (
        typeof value !== "string" &&
        typeof value !== "number" &&
        typeof value !== "boolean"
      ) {
        context.result.diagnostics.push({
          message: `${phase} step "${step.name}" could not capture ${name} from JSON path ${jsonPathExpression}.`,
        });
        return false;
      }
      context.variables.set(name, String(value));
    }
    return true;
  } catch (error) {
    context.result.diagnostics.push({
      message: `${phase} step "${step.name}" failed: ${error instanceof Error ? error.message : "unknown error"}`,
    });
    return false;
  }
}

async function runScenario(
  context: AttackContext,
  scenario: AttackScenario,
  sourceReport: ScanResult | undefined,
): Promise<AttackScenarioResult> {
  let setupOk = true;
  try {
    for (const step of scenario.setup ?? []) {
      if (!(await runStep(context, scenario, step, "setup"))) {
        setupOk = false;
        break;
      }
    }
    if (!setupOk)
      return { name: scenario.name, kind: scenario.kind, status: "incomplete" };

    let response: Response | undefined;
    try {
      response = await executeRequest(
        context,
        scenario,
        { ...scenario.attack, identity: scenario.attackerIdentity },
        "attack",
      );
    } catch (error) {
      context.result.diagnostics.push({
        message: `attack step "${scenario.attack.name}" failed: ${error instanceof Error ? error.message : "unknown error"}`,
      });
      return { name: scenario.name, kind: scenario.kind, status: "incomplete" };
    }
    if (!response)
      return { name: scenario.name, kind: scenario.kind, status: "incomplete" };

    context.result.metrics.sinks++;
    await response.body?.cancel();
      const expected =
      scenario.expect?.statuses ??
      scenario.denyStatuses ??
      (scenario.attack.expectStatus !== undefined
        ? [scenario.attack.expectStatus]
        : [401, 403, 404]);
    const statusMatches = expected.includes(response.status);
    const headersMatch = Object.entries(scenario.expect?.headers ?? {}).every(
      ([name, expectedValue]) =>
        response.headers.get(name)?.toLowerCase() === expectedValue.toLowerCase(),
    );
    const absentHeadersMatch = (scenario.expect?.absentHeaders ?? []).every(
      (name) => response.headers.get(name) === null,
    );

    if (statusMatches && headersMatch && absentHeadersMatch) {
      addGraph(
        context,
        scenario,
        undefined,
        sourceFindingFor(scenario, sourceReport),
      );
      return { name: scenario.name, kind: scenario.kind, status: "passed" };
    }
    if (response.status >= 500) {
      context.result.diagnostics.push({
        message: `Scenario "${scenario.name}" received HTTP ${response.status}; no authorization vulnerability was confirmed.`,
      });
      addGraph(
        context,
        scenario,
        undefined,
        sourceFindingFor(scenario, sourceReport),
      );
      return { name: scenario.name, kind: scenario.kind, status: "incomplete" };
    }

    const confirmed = activeFinding(
      context,
      scenario,
      response.status,
      sourceReport,
    );
    for (const [name, expectedValue] of Object.entries(
      scenario.expect?.headers ?? {},
    )) {
      const observed = response.headers.get(name);
      confirmed.evidence.push(
        `Observed response header ${name}: ${observed ?? "<absent>"}; expected: ${expectedValue}`,
      );
    }
    for (const name of scenario.expect?.absentHeaders ?? []) {
      const observed = response.headers.get(name);
      if (observed !== null)
        confirmed.evidence.push(
          `Observed response header ${name}: ${observed}; expected absent`,
        );
    }
    context.result.findings.push(confirmed);
    addGraph(
      context,
      scenario,
      confirmed.id,
      sourceFindingFor(scenario, sourceReport),
    );
    return {
      name: scenario.name,
      kind: scenario.kind,
      status: "confirmed",
      findingId: confirmed.id,
    };
  } finally {
    for (const step of [...(scenario.cleanup ?? [])].reverse())
      await runStep(context, scenario, step, "cleanup");
  }
}

export async function attack(
  targetValue: string,
  configValue: Config | AttackConfig,
  options: { signal?: AbortSignal; sourceReport?: ScanResult } = {},
): Promise<ScanResult> {
  const start = performance.now();
  const target = parseTarget(targetValue);
  const attackConfig =
    "scope" in configValue
      ? validateAttackConfig(configValue)
      : validateAttackConfig(configValue.attack);
  assertScopeFresh(attackConfig);
  if (!loopback(target.hostname) && !attackConfig.scope.authorizationId)
    throw new Error(
      "Remote attack targets require attack.scope.authorizationId for auditability.",
    );
  if (!targetAllowed(target, attackConfig))
    throw new Error(
      "Attack target is blocked. Remote origins require an exact attack.scope.allowedTargets entry.",
    );

  const result: ScanResult = {
    version: "0.2.0",
    root: target.origin,
    findings: [],
    diagnostics: [],
    graph: { nodes: [], edges: [] },
    metrics: {
      files: 0,
      routes: attackConfig.scenarios.length,
      sinks: 0,
      durationMs: 0,
      memoryBytes: 0,
    },
    coverage: { source: false, database: false, runtime: true },
    attack: {
      target: target.origin,
      environment: attackConfig.scope.environment,
      authorizationId: attackConfig.scope.authorizationId,
      configHash: createHash("sha256")
        .update(JSON.stringify(attackConfig))
        .digest("hex"),
      startedAt: new Date().toISOString(),
      requestCount: 0,
      serverErrors: 0,
      scenarios: [],
      audit: [],
    },
  };
  const attackSummary = result.attack!;
  const context: AttackContext = {
    target,
    config: attackConfig,
    result,
    variables: new Map(),
    signal: options.signal,
    requestCount: 0,
    serverErrors: 0,
    nextRequestAt: 0,
    sequence: 0,
  };

  for (const scenario of attackConfig.scenarios) {
    if (options.signal?.aborted) {
      result.diagnostics.push({ message: "Active attack run was cancelled." });
      break;
    }
    try {
      const scenarioResult = await runScenario(
        context,
        scenario,
        options.sourceReport,
      );
      attackSummary.scenarios.push(scenarioResult);
    } catch (error) {
      result.diagnostics.push({
        message: `Scenario "${scenario.name}" stopped: ${error instanceof Error ? error.message : "unknown error"}`,
      });
      attackSummary.scenarios.push({
        name: scenario.name,
        kind: scenario.kind,
        status: "incomplete",
      });
      if (/circuit breaker|budget exceeded/.test(String(error))) break;
    }
  }

  result.findings.sort((a, b) => a.id.localeCompare(b.id));
  attackSummary.requestCount = context.requestCount;
  attackSummary.serverErrors = context.serverErrors;
  result.metrics.durationMs = Math.round(performance.now() - start);
  result.metrics.memoryBytes = process.memoryUsage().rss;
  return result;
}
