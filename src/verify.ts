import { randomUUID } from "node:crypto";
import { performance } from "node:perf_hooks";
import { finding } from "./findings.js";
import type {
  Config,
  ScanResult,
  VerifyAssertion,
  VerifyJson,
  VerifyLifecycleRequest,
} from "./model.js";

interface RuntimeContext {
  target: URL;
  config: NonNullable<Config["verify"]>;
  result: ScanResult;
  variables: Map<string, string>;
  signal?: AbortSignal;
  requestCount: number;
  nextRequestAt: number;
  pacing: Promise<void>;
}

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

function severity(assertion: VerifyAssertion): "CRITICAL" | "HIGH" {
  return assertion.dimension === "tenant" ? "CRITICAL" : "HIGH";
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

function requestPath(path: string, variables: Map<string, string>): string {
  return path.replace(
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
      const name = value.slice("$env:".length);
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

function authToken(
  authEnv: string | undefined,
  authVar: string | undefined,
  variables: Map<string, string>,
): string | undefined {
  if (authEnv) {
    const token = process.env[authEnv];
    if (!token) throw new Error(`Missing environment variable ${authEnv}.`);
    return token;
  }
  if (authVar) {
    const token = variables.get(authVar);
    if (!token) throw new Error(`Missing captured variable ${authVar}.`);
    return token;
  }
  return undefined;
}

async function pace(context: RuntimeContext): Promise<boolean> {
  let release!: () => void;
  const previous = context.pacing;
  context.pacing = new Promise<void>((resolve) => {
    release = resolve;
  });
  await previous;
  try {
    if (context.signal?.aborted) return false;
    const rate = context.config.rateLimitPerSecond ?? 5;
    const wait = Math.max(0, context.nextRequestAt - Date.now());
    if (wait) await new Promise((resolve) => setTimeout(resolve, wait));
    if (context.signal?.aborted) return false;
    context.nextRequestAt = Date.now() + Math.ceil(1000 / rate);
    return true;
  } finally {
    release();
  }
}

function consumeBudget(context: RuntimeContext): void {
  context.requestCount++;
  const max = context.config.maxRequests ?? 100;
  if (context.requestCount > max)
    throw new Error(`Verification request budget exceeded (${max}).`);
}

async function request(
  context: RuntimeContext,
  input: {
    path: string;
    method: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE";
    authEnv?: string;
    authVar?: string;
    body?: VerifyJson;
  },
): Promise<Response | undefined> {
  if (!(await pace(context))) return undefined;
  consumeBudget(context);
  const path = requestPath(input.path, context.variables);
  const url = new URL(path, context.target);
  if (url.origin !== context.target.origin)
    throw new Error("Verification request escaped the target origin.");
  const headers = new Headers({
    accept: "application/json, text/plain;q=0.5",
    "user-agent": "REAPER/0.2.0 authorized-verification",
  });
  const token = authToken(input.authEnv, input.authVar, context.variables);
  if (token) headers.set("authorization", `Bearer ${token}`);
  let body: string | undefined;
  if (input.body !== undefined) {
    headers.set("content-type", "application/json");
    body = JSON.stringify(bodyValue(input.body, context.variables));
  }
  const controller = new AbortController();
  const timeoutMs = context.config.timeoutMs ?? 5000;
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  const signal = context.signal
    ? AbortSignal.any([controller.signal, context.signal])
    : controller.signal;
  try {
    return await fetch(url, {
      method: input.method,
      headers,
      body,
      redirect: "manual",
      signal,
    });
  } finally {
    clearTimeout(timeout);
  }
}

async function limitedJson(
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
  return JSON.parse(text) as unknown;
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

async function lifecycle(
  context: RuntimeContext,
  requests: VerifyLifecycleRequest[],
  phase: "setup" | "teardown",
): Promise<void> {
  if (!requests.length) return;
  if (context.config.allowMutations !== true)
    throw new Error("Mutating lifecycle requests require allowMutations=true.");
  for (const item of requests) {
    try {
      const response = await request(context, item);
      if (!response) return;
      context.result.metrics.sinks++;
      const captured =
        item.capture && Object.keys(item.capture).length
          ? await limitedJson(response)
          : (await response.body?.cancel(), undefined);
      if (
        item.expectStatus !== undefined &&
        response.status !== item.expectStatus
      )
        context.result.diagnostics.push({
          message: `${phase} request "${item.name}" expected HTTP ${item.expectStatus} but received ${response.status}.`,
        });
      for (const [name, path] of Object.entries(item.capture ?? {})) {
        const value = jsonPath(captured, path);
        if (
          typeof value !== "string" &&
          typeof value !== "number" &&
          typeof value !== "boolean"
        ) {
          context.result.diagnostics.push({
            message: `${phase} request "${item.name}" could not capture ${name} from JSON path ${path}.`,
          });
          continue;
        }
        context.variables.set(name, String(value));
      }
    } catch (error) {
      const message =
        error instanceof Error && error.name === "AbortError"
          ? context.signal?.aborted
            ? "was cancelled"
            : "timed out"
          : "failed";
      context.result.diagnostics.push({
        message: `${phase} request "${item.name}" ${message}.`,
      });
      if (phase === "setup") return;
    }
  }
}

export interface DiscoveredEndpoint {
  method: "GET" | "HEAD";
  path: string;
  status?: number;
}

function openApiEndpoints(document: unknown): DiscoveredEndpoint[] {
  if (!document || typeof document !== "object") return [];
  const paths = (document as Record<string, unknown>).paths;
  if (!paths || typeof paths !== "object" || Array.isArray(paths)) return [];
  const endpoints: DiscoveredEndpoint[] = [];
  for (const [path, value] of Object.entries(
    paths as Record<string, unknown>,
  )) {
    if (!path.startsWith("/") || !value || typeof value !== "object") continue;
    const operations = value as Record<string, unknown>;
    for (const method of ["get", "head"])
      if (operations[method] && typeof operations[method] === "object")
        endpoints.push({
          method: method.toUpperCase() as "GET" | "HEAD",
          path,
        });
  }
  return [
    ...new Map(
      endpoints.map((endpoint) => [
        `${endpoint.method} ${endpoint.path}`,
        endpoint,
      ]),
    ).values(),
  ].sort((a, b) =>
    `${a.method} ${a.path}`.localeCompare(`${b.method} ${b.path}`),
  );
}

async function discoverWithContext(
  context: RuntimeContext,
): Promise<DiscoveredEndpoint[]> {
  if (context.config.discoverOpenApi !== true) return [];
  const paths = context.config.openApiPaths?.length
    ? context.config.openApiPaths
    : ["/openapi.json", "/swagger.json", "/api-docs", "/api/openapi.json"];
  for (const path of paths) {
    try {
      const response = await request(context, { path, method: "GET" });
      if (!response) return [];
      if (!response.ok) {
        await response.body?.cancel();
        continue;
      }
      const endpoints = openApiEndpoints(await limitedJson(response));
      if (!endpoints.length) continue;
      for (const endpoint of endpoints) {
        const label = `${endpoint.method} ${endpoint.path}`;
        const id = `route:runtime:${label}`;
        if (!context.result.graph.nodes.some((node) => node.id === id))
          context.result.graph.nodes.push({
            id,
            kind: "route",
            label,
          });
        if (
          context.config.probeDiscovered === true &&
          !/[{}]/.test(endpoint.path)
        ) {
          try {
            const probed = await request(context, {
              path: endpoint.path,
              method: endpoint.method,
              authEnv: context.config.discoveryAuthEnv,
            });
            if (probed) {
              endpoint.status = probed.status;
              await probed.body?.cancel();
              context.result.metrics.sinks++;
            }
          } catch (error) {
            context.result.diagnostics.push({
              message: `Discovery probe ${label} failed: ${error instanceof Error ? error.message : "unknown error"}.`,
            });
          }
        }
      }
      context.result.metrics.routes += endpoints.length;
      return endpoints;
    } catch {
      continue;
    }
  }
  context.result.diagnostics.push({
    message:
      "OpenAPI discovery was enabled, but no supported GET/HEAD endpoint document was found.",
  });
  return [];
}

export async function discoverRoutes(
  target: string,
  config: Config,
  options: { signal?: AbortSignal } = {},
): Promise<DiscoveredEndpoint[]> {
  const parsed = targetUrl(target);
  if (!config.verify)
    throw new Error("Verification configuration is required.");
  if (!authorizedTarget(parsed, config))
    throw new Error(
      "Remote discovery target is blocked. Add its exact origin to verify.allowedTargets.",
    );
  const result = runtimeResult(parsed);
  const context: RuntimeContext = {
    target: parsed,
    config: { ...config.verify, discoverOpenApi: true },
    result,
    variables: new Map(),
    signal: options.signal,
    requestCount: 0,
    nextRequestAt: 0,
    pacing: Promise.resolve(),
  };
  return discoverWithContext(context);
}

export async function discoverEndpoints(
  target: string,
  config: Config,
  options: { signal?: AbortSignal } = {},
): Promise<string[]> {
  return (await discoverRoutes(target, config, options)).map(
    (endpoint) => `${endpoint.method} ${endpoint.path}`,
  );
}

async function syntheticUsers(
  context: RuntimeContext,
): Promise<() => Promise<void>> {
  const synthetic = context.config.syntheticUsers;
  if (!synthetic) return async () => {};
  if (context.config.allowMutations !== true)
    throw new Error("Synthetic users require allowMutations=true.");
  const count = synthetic.count ?? 2;
  const run = randomUUID().slice(0, 12);
  const created: number[] = [];
  for (let index = 1; index <= count; index++) {
    context.variables.set("SYNTHETIC_INDEX", String(index));
    context.variables.set("SYNTHETIC_RUN", run);
    const response = await request(context, {
      path: synthetic.path,
      method: synthetic.method ?? "POST",
      body: synthetic.body,
    });
    if (!response) break;
    context.result.metrics.sinks++;
    const body = await limitedJson(response);
    if (
      synthetic.expectStatus !== undefined &&
      response.status !== synthetic.expectStatus
    ) {
      context.result.diagnostics.push({
        message: `Synthetic user ${index} expected HTTP ${synthetic.expectStatus} but received ${response.status}.`,
      });
      break;
    }
    const token = jsonPath(body, synthetic.tokenPath);
    const id = synthetic.idPath ? jsonPath(body, synthetic.idPath) : undefined;
    if (typeof token !== "string" || !token) {
      context.result.diagnostics.push({
        message: `Synthetic user ${index} token capture failed at ${synthetic.tokenPath}.`,
      });
      break;
    }
    context.variables.set(`USER_${index}_TOKEN`, token);
    if (
      synthetic.idPath &&
      !["string", "number", "boolean"].includes(typeof id)
    ) {
      context.result.diagnostics.push({
        message: `Synthetic user ${index} id capture failed at ${synthetic.idPath}.`,
      });
      break;
    }
    if (id !== undefined) context.variables.set(`USER_${index}_ID`, String(id));
    created.push(index);
  }

  return async () => {
    if (!synthetic.cleanup) return;
    for (const index of created.reverse()) {
      context.variables.set(
        "USER_ID",
        context.variables.get(`USER_${index}_ID`) ?? "",
      );
      context.variables.set(
        "CURRENT_USER_TOKEN",
        context.variables.get(`USER_${index}_TOKEN`) ?? "",
      );
      try {
        const response = await request(context, {
          path: synthetic.cleanup.path,
          method: synthetic.cleanup.method ?? "DELETE",
          authVar: "CURRENT_USER_TOKEN",
        });
        if (!response) continue;
        context.result.metrics.sinks++;
        await response.body?.cancel();
        if (
          synthetic.cleanup.expectStatus !== undefined &&
          response.status !== synthetic.cleanup.expectStatus
        )
          context.result.diagnostics.push({
            message: `Synthetic user ${index} cleanup expected HTTP ${synthetic.cleanup.expectStatus} but received ${response.status}.`,
          });
      } catch {
        context.result.diagnostics.push({
          message: `Synthetic user ${index} cleanup failed.`,
        });
      }
    }
  };
}

async function executeAssertion(
  context: RuntimeContext,
  assertion: VerifyAssertion,
): Promise<void> {
  try {
    const response = await request(context, {
      path: assertion.path,
      method: assertion.method ?? "GET",
      authEnv: assertion.authEnv,
      authVar: assertion.authVar,
    });
    if (!response) return;
    await response.body?.cancel();
    context.result.metrics.sinks++;
    if (response.status === assertion.expectStatus) return;

    const resolvedPath = requestPath(assertion.path, context.variables);
    const route = `${assertion.method ?? "GET"} ${
      new URL(resolvedPath, context.target).pathname
    }`;
    const loc = {
      file: `runtime/${context.target.hostname}`,
      line: 1,
      column: 1,
    };
    context.result.findings.push(
      finding(
        {
          ...loc,
          ruleId: "REAPER-VERIFY-001",
          title: "Configured authorization assertion failed",
          description: `Assertion "${assertion.name}" expected HTTP ${assertion.expectStatus} but received ${response.status}.`,
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
              : assertion.authVar
                ? `Authentication token supplied from captured scenario variable ${assertion.authVar}.`
                : "Request was sent without an Authorization header.",
          ],
          dataFlow: [],
          recommendation:
            "Review the target route's authentication, ownership/tenant checks and database policy path. Re-run this assertion after remediation.",
        },
        `verify:${context.target.origin}:${assertion.method ?? "GET"}:${assertion.path}:${assertion.name}`,
      ),
    );
  } catch (error) {
    const reason =
      error instanceof Error && error.name === "AbortError"
        ? context.signal?.aborted
          ? "was cancelled"
          : "timed out"
        : error instanceof Error
          ? error.message
          : "failed before an HTTP status was received";
    context.result.diagnostics.push({
      message: `Verification assertion "${assertion.name}" ${reason}.`,
    });
  }
}

export async function verify(
  target: string,
  config: Config,
  options: { signal?: AbortSignal } = {},
): Promise<ScanResult> {
  const start = performance.now();
  const parsed = targetUrl(target);
  if (!config.verify)
    throw new Error("Verification configuration is required.");
  if (!authorizedTarget(parsed, config))
    throw new Error(
      "Remote verification target is blocked. Add its exact origin to verify.allowedTargets.",
    );

  const result = runtimeResult(parsed);
  const context: RuntimeContext = {
    target: parsed,
    config: config.verify,
    result,
    variables: new Map(),
    signal: options.signal,
    requestCount: 0,
    nextRequestAt: 0,
    pacing: Promise.resolve(),
  };
  const concurrency = Math.min(config.verify.concurrency ?? 2, 8);
  let cursor = 0;

  let cleanupSynthetic = async () => {};
  try {
    await discoverWithContext(context);
    await lifecycle(context, config.verify.setup ?? [], "setup");
    cleanupSynthetic = await syntheticUsers(context);

    async function worker(): Promise<void> {
      for (;;) {
        if (options.signal?.aborted) return;
        const index = cursor++;
        const assertion = config.verify!.assertions[index];
        if (!assertion) return;
        await executeAssertion(context, assertion);
      }
    }

    await Promise.all(
      Array.from(
        {
          length: Math.min(
            concurrency,
            Math.max(1, config.verify.assertions.length),
          ),
        },
        () => worker(),
      ),
    );
  } finally {
    await cleanupSynthetic();
    await lifecycle(context, config.verify.teardown ?? [], "teardown");
  }

  result.findings.sort((a, b) => a.id.localeCompare(b.id));
  result.metrics.durationMs = Math.round(performance.now() - start);
  result.metrics.memoryBytes = process.memoryUsage().rss;
  return result;
}
