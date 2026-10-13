import { randomUUID } from "node:crypto";
import { lookup } from "node:dns/promises";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { performance } from "node:perf_hooks";
import { Readable } from "node:stream";
import { finding } from "./findings.js";
import { validateAttackConfig } from "./attack-config.js";
import {
  EnvironmentSecretProvider,
  type SecretProvider,
  type SecretRequestContext,
} from "./secrets.js";
import {
  authorizationScopeDigest,
  verifyAuthorizationScope,
  type SignedAuthorizationScope,
} from "./scope.js";
import type { KeyLike } from "node:crypto";
import { ENGINE_VERSION } from "./model.js";
import {
  journalError,
  type ExecutionJournalRecord,
  type ExecutionJournalStore,
  type JournalCleanupPlan,
  type JournalIdentityRef,
} from "./journal.js";
import type { ScopeReplayStore } from "./replay.js";
import type { AuditJson, AuditStore, AuditEventType } from "./audit.js";
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
  cleanupRequestCount: number;
  nextRequestAt: number;
  pacing: Promise<void>;
  consecutiveServerErrors: number;
  baselineAddresses: string[];
  signal?: AbortSignal;
  scopeExpiresAt?: number;
  secrets: SecretProvider;
  secretReferences: Set<string>;
  secretValues: Set<string>;
  journal?: ExecutionJournalStore;
  audit?: AuditStore;
  plannedJournalScenarios: Set<string>;
  executionFailed: boolean;
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

function isForbiddenInfrastructureAddress(address: string): boolean {
  const normalized = address.toLowerCase();
  const mapped = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isForbiddenInfrastructureAddress(mapped[1]!);
  const ipv4 = normalized.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (ipv4) {
    const a = Number(ipv4[1]);
    const b = Number(ipv4[2]);
    return a === 0 || (a === 169 && b === 254) || a >= 224;
  }
  if (normalized === "::") return true;
  const first = Number.parseInt(normalized.split(":")[0] || "0", 16);
  return (first & 0xffc0) === 0xfe80 || (first & 0xff00) === 0xff00;
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
      a === 10 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168)
    );
  }
  const first = Number.parseInt(normalized.split(":")[0] || "0", 16);
  return (first & 0xfe00) === 0xfc00;
}

function assertNetworkScope(addresses: string[], config: AttackConfig): void {
  const forbidden = addresses.filter(
    (address) =>
      isForbiddenInfrastructureAddress(address) && !isLoopbackAddress(address),
  );
  if (forbidden.length)
    throw new Error(
      "Attack target resolves to a link-local, unspecified, multicast or reserved infrastructure address; these targets are blocked even when private-network testing is enabled.",
    );
  const privateNonLoopback = addresses.filter(
    (address) => isPrivateAddress(address) && !isLoopbackAddress(address),
  );
  if (privateNonLoopback.length && config.allowPrivateNetwork !== true)
    throw new Error(
      "Attack target resolves to a private network; set attack.allowPrivateNetwork=true only for explicitly authorized internal assessments.",
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

function pinnedRequest(
  context: AttackContext,
  url: URL,
  input: {
    method: AttackStep["method"];
    headers: Headers;
    body?: string;
    signal: AbortSignal;
  },
): Promise<Response> {
  const address = context.baselineAddresses[0];
  if (!address) throw new Error("Attack target did not resolve to an address.");

  const headers: Record<string, string> = {};
  input.headers.forEach((value, key) => {
    headers[key] = value;
  });
  headers.host = context.target.host;
  headers["accept-encoding"] = "identity";

  return new Promise<Response>((resolve, reject) => {
    const onResponse = (incoming: import("node:http").IncomingMessage) => {
      const responseHeaders = new Headers();
      for (let index = 0; index < incoming.rawHeaders.length; index += 2) {
        const name = incoming.rawHeaders[index];
        const value = incoming.rawHeaders[index + 1];
        if (name && value !== undefined) responseHeaders.append(name, value);
      }
      const status = incoming.statusCode ?? 500;
      const noBody =
        input.method === "HEAD" || [204, 205, 304].includes(status);
      const responseBody = noBody
        ? null
        : (Readable.toWeb(incoming) as unknown as BodyInit);
      resolve(
        new Response(responseBody, {
          status,
          statusText: incoming.statusMessage,
          headers: responseHeaders,
        }),
      );
    };

    const common = {
      protocol: url.protocol,
      hostname: address,
      port: url.port || undefined,
      path: `${url.pathname}${url.search}`,
      method: input.method,
      headers,
      signal: input.signal,
      agent: false,
    };
    const request =
      url.protocol === "https:"
        ? httpsRequest(
            {
              ...common,
              servername: isIpLiteral(context.target.hostname)
                ? undefined
                : context.target.hostname,
              rejectUnauthorized: true,
            },
            onResponse,
          )
        : httpRequest(common, onResponse);
    request.once("error", reject);
    request.end(input.body);
  });
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
  resolveSecret: (reference: string, purpose: string) => Promise<string>,
): Promise<VerifyJson> {
  if (typeof value === "string") {
    if (value.startsWith("$env:")) {
      const name = value.slice(5);
      return resolveSecret(name, "request body");
    }
    return Promise.resolve(interpolate(value, variables));
  }
  if (Array.isArray(value))
    return Promise.all(
      value.map((entry) => bodyValue(entry, variables, resolveSecret)),
    );
  if (value && typeof value === "object")
    return Promise.all(
      Object.entries(value).map(async ([key, entry]) => [
        key,
        await bodyValue(entry, variables, resolveSecret),
      ]),
    ).then(
      (entries) => Object.fromEntries(entries) as { [key: string]: VerifyJson },
    );
  return Promise.resolve(value);
}

async function requiredSecret(
  context: AttackContext,
  reference: string,
  purpose: string,
): Promise<string> {
  const requestContext: SecretRequestContext = {
    runId: context.result.attack?.runId ?? "unknown",
    targetOrigin: context.target.origin,
    purpose,
  };
  // A provider may allocate a lease before returning or throwing. Register the
  // reference first so the run-level finally block always attempts revocation.
  context.secretReferences.add(reference);
  let value: string | undefined;
  try {
    value = await context.secrets.get(reference, requestContext);
  } catch {
    throw new Error(`Secret provider failed for ${purpose}.`);
  }
  if (typeof value !== "string" || value.length === 0)
    throw new Error(`Missing configured secret reference for ${purpose}.`);
  if (Buffer.byteLength(value, "utf8") > 16_384)
    throw new Error(
      `Configured secret exceeds the 16 KiB limit for ${purpose}.`,
    );
  context.secretValues.add(value);
  return value;
}

function redactKnownSecrets(value: unknown, secretValues: Set<string>): void {
  const secrets = [...secretValues]
    .filter(Boolean)
    .sort((a, b) => b.length - a.length);
  const redact = (text: string): string => {
    for (const secret of secrets) text = text.split(secret).join("[REDACTED]");
    return text;
  };
  const visit = (entry: unknown): void => {
    if (Array.isArray(entry)) {
      for (let index = 0; index < entry.length; index++)
        if (typeof entry[index] === "string")
          entry[index] = redact(entry[index] as string);
        else visit(entry[index]);
      return;
    }
    if (!entry || typeof entry !== "object") return;
    const record = entry as Record<string, unknown>;
    for (const key of Object.keys(record)) {
      if (typeof record[key] === "string")
        record[key] = redact(record[key] as string);
      else visit(record[key]);
    }
  };
  visit(value);
}

async function identityToken(
  identity: AttackIdentity | undefined,
  context: AttackContext,
): Promise<string | undefined> {
  if (!identity) return undefined;
  if (identity.tokenEnv)
    return requiredSecret(context, identity.tokenEnv, "identity token");
  if (identity.tokenVar) {
    const value = context.variables.get(identity.tokenVar);
    if (!value)
      throw new Error(`Missing captured variable ${identity.tokenVar}.`);
    context.secretValues.add(value);
    return value;
  }
  return undefined;
}

async function applyIdentityHeaders(
  headers: Headers,
  identity: AttackIdentity | undefined,
  context: AttackContext,
): Promise<void> {
  if (!identity) return;
  const token = await identityToken(identity, context);
  if (token) headers.set("authorization", `Bearer ${token}`);

  if (identity.cookie) {
    const value = identity.cookie.valueEnv
      ? await requiredSecret(
          context,
          identity.cookie.valueEnv,
          "identity cookie",
        )
      : context.variables.get(identity.cookie.valueVar!);
    if (!value && identity.cookie.valueVar)
      throw new Error(
        `Missing captured variable ${identity.cookie.valueVar} for identity cookie.`,
      );
    if (value) headers.set("cookie", `${identity.cookie.name}=${value}`);
    if (value && identity.cookie.valueVar) context.secretValues.add(value);
  }

  for (const [header, envName] of Object.entries(identity.headerEnvs ?? {})) {
    const value = await requiredSecret(context, envName, `header ${header}`);
    headers.set(header, value);
  }
  for (const [header, variableName] of Object.entries(
    identity.headerVars ?? {},
  )) {
    const value = context.variables.get(variableName);
    if (!value)
      throw new Error(
        `Missing captured variable ${variableName} for header ${header}.`,
      );
    context.secretValues.add(value);
    headers.set(header, value);
  }
}

function responseCookie(
  response: Response,
  cookieName: string,
): string | undefined {
  const headers = response.headers as Headers & {
    getSetCookie?: () => string[];
  };
  const values = headers.getSetCookie?.() ?? [];
  const fallback = response.headers.get("set-cookie");
  if (!values.length && fallback) values.push(fallback);
  for (const line of values) {
    const first = line.split(";", 1)[0] ?? "";
    const separator = first.indexOf("=");
    if (separator < 1) continue;
    if (first.slice(0, separator).trim() !== cookieName) continue;
    return first.slice(separator + 1);
  }
  return undefined;
}

async function persistentAudit(
  context: AttackContext,
  type: AuditEventType,
  data: Record<string, AuditJson> = {},
): Promise<void> {
  if (!context.audit) return;
  const runId = context.result.attack?.runId;
  if (!runId) throw new Error("Persistent audit requires an attack run id.");
  await context.audit.append(runId, { type, data });
}

function journalIdentity(
  identity: AttackIdentity | undefined,
): JournalIdentityRef | undefined {
  if (!identity) return undefined;
  if (
    identity.tokenVar ||
    identity.cookie?.valueVar ||
    Object.keys(identity.headerVars ?? {}).length > 0
  )
    throw new Error(
      "Crash-safe cleanup cannot depend on captured credential values; use environment-backed secret references.",
    );
  const result: JournalIdentityRef = {};
  if (identity.tokenEnv) result.tokenEnv = identity.tokenEnv;
  if (identity.cookie?.valueEnv)
    result.cookie = {
      name: identity.cookie.name,
      valueEnv: identity.cookie.valueEnv,
    };
  if (Object.keys(identity.headerEnvs ?? {}).length)
    result.headerEnvs = { ...identity.headerEnvs };
  return Object.keys(result).length ? result : undefined;
}

function journalTemplate(
  value: string,
  context: AttackContext,
  encode: boolean,
): string {
  return value.replace(
    /\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}/g,
    (_, name: string) => {
      const replacement = context.variables.get(name);
      if (replacement === undefined)
        throw new Error(
          `Crash-safe cleanup requires captured variable ${name} before the mutating request.`,
        );
      if (context.secretValues.has(replacement))
        throw new Error(
          `Crash-safe cleanup cannot persist secret captured variable ${name}.`,
        );
      return encode ? encodeURIComponent(replacement) : replacement;
    },
  );
}

function journalBody(
  value: VerifyJson,
  context: AttackContext,
): VerifyJson {
  if (typeof value === "string") {
    if (value.startsWith("$env:")) return value;
    return journalTemplate(value, context, false);
  }
  if (Array.isArray(value))
    return value.map((entry) => journalBody(entry, context));
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [
        key,
        journalBody(entry, context),
      ]),
    );
  return value;
}

async function ensureJournalCleanupPlanned(
  context: AttackContext,
  scenario: AttackScenario,
): Promise<void> {
  if (!context.journal || context.plannedJournalScenarios.has(scenario.id))
    return;
  const cleanup = [...(scenario.cleanup ?? [])].reverse();
  if (cleanup.length < 1)
    throw new Error(
      `Crash-safe mutation scenario ${scenario.id} requires cleanup steps.`,
    );
  const names = new Set<string>();
  const now = new Date().toISOString();
  const plans: JournalCleanupPlan[] = cleanup.map((step, index) => {
    if (names.has(step.name))
      throw new Error(
        `Crash-safe cleanup step names must be unique in scenario ${scenario.id}.`,
      );
    names.add(step.name);
    const method = step.method ?? "GET";
    if (!["POST", "PUT", "PATCH", "DELETE"].includes(method))
      throw new Error(
        `Crash-safe cleanup step ${step.name} must use a mutating HTTP method.`,
      );
    const allowedStatuses = step.expect?.allowedStatuses;
    if (
      !allowedStatuses?.length ||
      allowedStatuses.some((status) => status >= 500)
    )
      throw new Error(
        `Crash-safe cleanup step ${step.name} requires explicit non-5xx allowedStatuses.`,
      );
    const identity = step.actor
      ? journalIdentity(context.config.identities?.[step.actor])
      : undefined;
    return {
      id: `cleanup-${index + 1}-${scenario.id}`,
      scenarioId: scenario.id,
      stepName: step.name,
      method: method as "POST" | "PUT" | "PATCH" | "DELETE",
      path: journalTemplate(step.path, context, true),
      ...(step.actor ? { actor: step.actor } : {}),
      ...(identity ? { identity } : {}),
      ...(step.body !== undefined
        ? { body: journalBody(step.body, context) }
        : {}),
      allowedStatuses: [...allowedStatuses],
      attempts: 0,
      status: "PENDING" as const,
      plannedAt: now,
      updatedAt: now,
    };
  });
  const runId = context.result.attack?.runId;
  if (!runId) throw new Error("Execution journal requires an attack run id.");
  await context.journal.update(runId, (record) => {
    if (record.cleanups.some((plan) => plan.scenarioId === scenario.id)) return;
    record.cleanups.push(...plans);
  });
  context.plannedJournalScenarios.add(scenario.id);
  for (const plan of plans)
    await persistentAudit(context, "CLEANUP_PLANNED", {
      scenarioId: plan.scenarioId,
      step: plan.stepName,
      method: plan.method,
      path: plan.path,
    });
}

async function journalCleanupStarted(
  context: AttackContext,
  scenario: AttackScenario,
  step: AttackStep,
): Promise<JournalCleanupPlan | undefined> {
  if (!context.journal) return undefined;
  const runId = context.result.attack?.runId;
  if (!runId) throw new Error("Execution journal requires an attack run id.");
  let selected: JournalCleanupPlan | undefined;
  await context.journal.update(runId, (record) => {
    const plan = record.cleanups.find(
      (candidate) =>
        candidate.scenarioId === scenario.id &&
        candidate.stepName === step.name &&
        candidate.status !== "SUCCEEDED",
    );
    if (!plan)
      throw new Error(
        `No write-ahead cleanup plan exists for ${scenario.id}/${step.name}.`,
      );
    plan.status = "RUNNING";
    plan.attempts++;
    plan.updatedAt = new Date().toISOString();
    delete plan.lastError;
    record.status = "CLEANING";
    selected = structuredClone(plan);
  });
  await persistentAudit(context, "CLEANUP_STARTED", {
    scenarioId: scenario.id,
    step: step.name,
  });
  return selected;
}

async function journalCleanupSucceeded(
  context: AttackContext,
  plan: JournalCleanupPlan,
  status: number,
): Promise<void> {
  if (!context.journal) return;
  const runId = context.result.attack?.runId;
  if (!runId) throw new Error("Execution journal requires an attack run id.");
  await context.journal.update(runId, (record) => {
    const current = record.cleanups.find((candidate) => candidate.id === plan.id);
    if (!current) throw new Error("Execution journal cleanup plan disappeared.");
    current.status = "SUCCEEDED";
    current.updatedAt = new Date().toISOString();
    delete current.lastError;
  });
  await persistentAudit(context, "CLEANUP_SUCCEEDED", {
    scenarioId: plan.scenarioId,
    step: plan.stepName,
    status,
  });
}

async function journalCleanupFailed(
  context: AttackContext,
  scenario: AttackScenario,
  step: AttackStep,
  error: unknown,
): Promise<void> {
  if (!context.journal) return;
  const runId = context.result.attack?.runId;
  if (!runId) throw new Error("Execution journal requires an attack run id.");
  await context.journal.update(runId, (record) => {
    const current = record.cleanups.find(
      (candidate) =>
        candidate.scenarioId === scenario.id &&
        candidate.stepName === step.name &&
        candidate.status !== "SUCCEEDED",
    );
    if (!current) return;
    current.status = "FAILED";
    current.lastError = journalError(error);
    current.updatedAt = new Date().toISOString();
    record.status = "CLEANUP_FAILED";
  });
  await persistentAudit(context, "CLEANUP_FAILED", {
    scenarioId: scenario.id,
    step: step.name,
    error: journalError(error),
  });
}

async function pace(context: AttackContext, cleanup = false): Promise<boolean> {
  let release!: () => void;
  const previous = context.pacing;
  context.pacing = new Promise<void>((resolve) => {
    release = resolve;
  });
  await previous;
  try {
    if (!cleanup && context.signal?.aborted) return false;
    const rate = context.config.rateLimitPerSecond ?? 3;
    const wait = Math.max(0, context.nextRequestAt - Date.now());
    if (wait) await new Promise((resolve) => setTimeout(resolve, wait));
    if (!cleanup && context.signal?.aborted) return false;
    context.nextRequestAt = Date.now() + Math.ceil(1000 / rate);
    return true;
  } finally {
    release();
  }
}

function consumeBudget(context: AttackContext, cleanup = false): void {
  if (cleanup) {
    const maxCleanup = context.config.maxCleanupRequests ?? 100;
    if (context.cleanupRequestCount >= maxCleanup)
      throw new Error(
        `Attack cleanup request budget exceeded (${maxCleanup}).`,
      );
    context.cleanupRequestCount++;
    return;
  }
  const max = context.config.maxRequests ?? 100;
  if (context.requestCount >= max)
    throw new Error(`Attack request budget exceeded (${max}).`);
  context.requestCount++;
}

function assertAuthorizationActive(
  context: AttackContext,
  cleanup: boolean,
): void {
  if (cleanup) return;
  const expiresAt = context.config.authorization.expiresAt;
  if (expiresAt && Date.parse(expiresAt) <= Date.now())
    throw new Error("Attack authorization expired during the run.");
  if (
    context.scopeExpiresAt !== undefined &&
    context.scopeExpiresAt <= Date.now()
  )
    throw new Error("Signed authorization scope expired during the run.");
}

async function limitedJson(response: Response): Promise<unknown> {
  const maxBytes = 65536;
  const contentLength = response.headers.get("content-length");
  const declared = contentLength === null ? undefined : Number(contentLength);
  if (
    declared !== undefined &&
    (!Number.isSafeInteger(declared) || declared < 0)
  ) {
    await response.body?.cancel();
    throw new Error(
      "Response has an invalid content length for attack capture.",
    );
  }
  if (declared !== undefined && declared > maxBytes) {
    await response.body?.cancel();
    throw new Error("Response is too large for attack capture.");
  }
  if (!response.body) return undefined;

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new Error("Response is too large for attack capture.");
      }
      chunks.push(value);
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
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
  if (!(await pace(context, cleanup))) throw new Error("Attack run cancelled.");
  assertAuthorizationActive(context, cleanup);
  consumeBudget(context, cleanup);
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
  await applyIdentityHeaders(headers, identity, context);

  let body: string | undefined;
  if (step.body !== undefined) {
    headers.set("content-type", "application/json");
    body = JSON.stringify(
      await bodyValue(step.body, context.variables, (reference, purpose) =>
        requiredSecret(context, reference, purpose),
      ),
    );
  }

  assertAuthorizationActive(context, cleanup);

  const controller = new AbortController();
  const timeout = setTimeout(
    () => controller.abort(),
    context.config.timeoutMs ?? 5000,
  );
  const signal =
    !cleanup && context.signal
      ? AbortSignal.any([controller.signal, context.signal])
      : controller.signal;

  let response: Response;
  try {
    response = await pinnedRequest(context, url, {
      method,
      headers,
      body,
      signal,
    });
  } catch (error) {
    clearTimeout(timeout);
    throw error;
  }
  try {
    context.result.metrics.sinks++;

    if (step.captureCookies && Object.keys(step.captureCookies).length) {
      for (const [variableName, cookieName] of Object.entries(
        step.captureCookies,
      )) {
        const value = responseCookie(response, cookieName);
        if (!value)
          throw new Error(
            `Attack cookie capture ${variableName} failed for cookie ${cookieName}.`,
          );
        context.variables.set(variableName, value);
        context.secretValues.add(value);
      }
    }

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
        parsed = await limitedJson(response);
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
  } finally {
    clearTimeout(timeout);
    if (!response.bodyUsed) await response.body?.cancel().catch(() => {});
  }
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
        context.variables.set(
          "RESOURCE_OWNER",
          interpolate(resource.ownerValue ?? resource.owner, context.variables),
        );
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
  options: {
    signal?: AbortSignal;
    runId?: string;
    rulePackVersion?: string;
    workspaceId?: string;
    projectId?: string;
    scopeManifest?: SignedAuthorizationScope;
    trustedScopeKeys?: Record<string, KeyLike | string | Buffer>;
    secretProvider?: SecretProvider;
  } = {},
): Promise<ScanResult> {
  if (!config.attack)
    throw new Error("Attack mode requires an attack configuration.");
  const attack = validateAttackConfig(config.attack);
  const parsed = targetUrl(target);
  if (!authorizedTarget(parsed, attack))
    throw new Error("Attack target is blocked by the exact-origin allowlist.");

  if (attack.requireSignedScope && !options.scopeManifest)
    throw new Error(
      "Attack configuration requires a signed authorization scope.",
    );
  let scopeExpiry: number | undefined;
  let verifiedScope: ReturnType<typeof verifyAuthorizationScope> | undefined;
  let activeSignal = options.signal;
  if (options.scopeManifest) {
    if (!options.trustedScopeKeys)
      throw new Error(
        "Trusted public keys are required to verify the signed scope.",
      );
    const scope = verifyAuthorizationScope(
      options.scopeManifest,
      options.trustedScopeKeys,
      {
        target: parsed.origin,
        environment: attack.authorization.environment,
        reference: attack.authorization.reference,
      },
    );
    verifiedScope = scope;
    if (
      attack.allowMutations === true &&
      !scope.permissions.includes("mutations")
    )
      throw new Error("Signed authorization scope does not permit mutations.");
    if (
      attack.allowPrivateNetwork === true &&
      !scope.permissions.includes("internalNetwork")
    )
      throw new Error(
        "Signed authorization scope does not permit internal network targets.",
      );
    attack.maxRequests = Math.min(
      attack.maxRequests ?? scope.limits.maxRequests,
      scope.limits.maxRequests,
    );
    attack.maxCleanupRequests = Math.min(
      attack.maxCleanupRequests ?? scope.limits.maxCleanupRequests,
      scope.limits.maxCleanupRequests,
    );
    attack.rateLimitPerSecond = Math.min(
      attack.rateLimitPerSecond ?? scope.limits.rateLimitPerSecond,
      scope.limits.rateLimitPerSecond,
    );
    scopeExpiry = Date.parse(scope.expiresAt);
    activeSignal = activeSignal
      ? AbortSignal.any([
          activeSignal,
          AbortSignal.timeout(scope.limits.deadlineMs),
        ])
      : AbortSignal.timeout(scope.limits.deadlineMs);
  }

  const started = performance.now();
  const startedAt = new Date().toISOString();
  const result = resultFor(parsed);
  result.attack = {
    runId: options.runId ?? randomUUID(),
    engineVersion: ENGINE_VERSION,
    ...(options.rulePackVersion
      ? { rulePackVersion: options.rulePackVersion }
      : {}),
    ...(options.workspaceId ? { workspaceId: options.workspaceId } : {}),
    ...(options.projectId ? { projectId: options.projectId } : {}),
    target: parsed.origin,
    authorizationReference: attack.authorization.reference,
    authorizationExpiresAt: attack.authorization.expiresAt,
    ...(options.scopeManifest && verifiedScope
      ? {
          signedScope: {
            keyId: options.scopeManifest.keyId,
            assessmentId: verifiedScope.assessmentId,
            issuer: verifiedScope.issuer,
            expiresAt: verifiedScope.expiresAt,
            digest: authorizationScopeDigest(options.scopeManifest),
          },
        }
      : {}),
    environment: attack.authorization.environment,
    startedAt,
    completedAt: startedAt,
    requests: 0,
    cleanupRequests: 0,
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
    cleanupRequestCount: 0,
    nextRequestAt: 0,
    pacing: Promise.resolve(),
    consecutiveServerErrors: 0,
    baselineAddresses,
    signal: activeSignal,
    scopeExpiresAt: scopeExpiry,
    secrets: options.secretProvider ?? new EnvironmentSecretProvider(),
    secretReferences: new Set<string>(),
    secretValues: new Set<string>(),
  };

  try {
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
        if (context.signal?.aborted || context.consecutiveServerErrors > 0)
          break;
      }
  } finally {
    if (context.secrets.revoke)
      for (const reference of context.secretReferences)
        try {
          await context.secrets.revoke(reference, {
            runId: result.attack.runId,
            targetOrigin: parsed.origin,
            purpose: "attack run completion",
          });
        } catch {
          result.diagnostics.push({
            message:
              "A configured secret lease could not be revoked after the attack run.",
          });
        }
  }

  result.metrics.durationMs = Math.round(performance.now() - started);
  result.metrics.memoryBytes = process.memoryUsage().rss;
  result.attack.requests = context.requestCount + context.cleanupRequestCount;
  result.attack.cleanupRequests = context.cleanupRequestCount;
  result.attack.completedAt = new Date().toISOString();
  redactKnownSecrets(result, context.secretValues);
  return result;
}
