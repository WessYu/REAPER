import type { ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ENGINE_VERSION, type Config, type ScanResult } from "./model.js";
import {
  verifyAuthorizationScope,
  type SignedAuthorizationScope,
} from "./scope.js";
import { parseRunnerTrustConfig, RUNNER_TRUST_ENV } from "./runner-trust.js";
import {
  ProcessIsolationProvider,
  assertRunnerIsolation,
  type RunnerIsolationMode,
  type RunnerIsolationProvider,
} from "./isolation.js";
import { ensureSecureDirectory } from "./secure-store.js";

export interface AttackJob {
  version: 1;
  runId: string;
  target: string;
  authorization: {
    reference: string;
    environment: "local" | "preview" | "staging" | "production";
    expiresAt?: string;
  };
  config: Config;
  limits: {
    deadlineMs: number;
    cleanupGraceMs: number;
    memoryMb: number;
    maxOutputBytes: number;
  };
  engineVersion: string;
  rulePackVersion?: string;
  createdAt: string;
  deadline: string;
  workspaceId?: string;
  projectId?: string;
  scopeManifest?: SignedAuthorizationScope;
}

export type AttackJobOutcome =
  | { status: "COMPLETED"; exitCode: 0; result: ScanResult }
  | {
      status: "FAILED" | "INTERRUPTED" | "CLEANUP_FAILED";
      exitCode: number | null;
      reason: string;
      result?: ScanResult;
    };

const JOB_FILE = fileURLToPath(new URL("./runner-worker.js", import.meta.url));
const STDIO_LIMIT = 16 * 1024;
const MAX_JOB_BYTES = 5 * 1024 * 1024;
const MAX_JOB_OUTPUT = 10 * 1024 * 1024;

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function assertJob(value: AttackJob): void {
  if (!isRecord(value) || value.version !== 1)
    throw new Error("Attack job protocol version is invalid.");
  if (
    Object.hasOwn(value, "trustedScopeKeys") ||
    Object.hasOwn(value, "trustedKeys") ||
    Object.hasOwn(value, "publicKey")
  )
    throw new Error("Attack job must not supply its own verification keys.");
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      value.runId,
    )
  )
    throw new Error("Attack job runId is invalid.");
  if (!isRecord(value.config?.attack))
    throw new Error("Attack job requires attack configuration.");
  const target = new URL(value.target);
  if (
    !["http:", "https:"].includes(target.protocol) ||
    target.origin !== value.target ||
    target.username ||
    target.password
  )
    throw new Error("Attack job target must be an exact HTTP(S) origin.");
  if (!value.config.attack.allowedTargets.includes(target.origin))
    throw new Error("Attack job target is outside the configured allowlist.");
  const auth = value.authorization;
  const configAuth = value.config.attack.authorization;
  if (
    !isRecord(auth) ||
    !isRecord(configAuth) ||
    auth.reference !== configAuth.reference ||
    auth.environment !== configAuth.environment ||
    auth.expiresAt !== configAuth.expiresAt
  )
    throw new Error("Attack job authorization does not match its config.");
  if (
    !isRecord(value.limits) ||
    !Number.isSafeInteger(value.limits.deadlineMs) ||
    value.limits.deadlineMs < 100 ||
    value.limits.deadlineMs > 30 * 60_000 ||
    !Number.isSafeInteger(value.limits.cleanupGraceMs) ||
    value.limits.cleanupGraceMs < 0 ||
    value.limits.cleanupGraceMs > 60_000 ||
    !Number.isSafeInteger(value.limits.memoryMb) ||
    value.limits.memoryMb < 64 ||
    value.limits.memoryMb > 2048 ||
    !Number.isSafeInteger(value.limits.maxOutputBytes) ||
    value.limits.maxOutputBytes < 1024 ||
    value.limits.maxOutputBytes > MAX_JOB_OUTPUT
  )
    throw new Error(
      "Attack job limits are invalid or exceed supported bounds.",
    );
  if (
    typeof value.engineVersion !== "string" ||
    value.engineVersion !== ENGINE_VERSION
  )
    throw new Error("Attack job engineVersion does not match this runner.");
  if (
    value.rulePackVersion !== undefined &&
    (typeof value.rulePackVersion !== "string" ||
      value.rulePackVersion.length > 100)
  )
    throw new Error("Attack job rulePackVersion is invalid.");
  for (const [name, timestamp] of [
    ["createdAt", value.createdAt],
    ["deadline", value.deadline],
  ] as const) {
    if (
      typeof timestamp !== "string" ||
      !Number.isFinite(Date.parse(timestamp)) ||
      new Date(timestamp).toISOString() !== timestamp
    )
      throw new Error(`Attack job ${name} is invalid.`);
  }
  const createdAt = Date.parse(value.createdAt);
  const deadline = Date.parse(value.deadline);
  if (
    deadline <= Date.now() ||
    deadline <= createdAt ||
    deadline - createdAt > value.limits.deadlineMs
  )
    throw new Error("Attack job deadline is expired or exceeds its limit.");
  for (const key of ["workspaceId", "projectId"] as const)
    if (
      value[key] !== undefined &&
      (typeof value[key] !== "string" ||
        !value[key]!.trim() ||
        value[key]!.length > 200)
    )
      throw new Error(`Attack job ${key} is invalid.`);
}

function secretReferences(config: Config): Set<string> {
  const refs = new Set<string>();
  const identities = config.attack?.identities ?? {};
  for (const identity of Object.values(identities)) {
    if (identity.tokenEnv) refs.add(identity.tokenEnv);
    if (identity.cookie?.valueEnv) refs.add(identity.cookie.valueEnv);
    for (const ref of Object.values(identity.headerEnvs ?? {})) refs.add(ref);
  }
  const visit = (value: unknown): void => {
    if (typeof value === "string" && value.startsWith("$env:"))
      refs.add(value.slice(5));
    else if (Array.isArray(value)) value.forEach(visit);
    else if (isRecord(value)) Object.values(value).forEach(visit);
  };
  for (const scenario of config.attack?.scenarios ?? [])
    for (const step of [...scenario.steps, ...(scenario.cleanup ?? [])])
      visit(step.body);
  for (const ref of refs)
    if (!/^[A-Z_][A-Z0-9_]*$/i.test(ref) || [
        "REAPER_RUNNER_MODE",
        "REAPER_RUNNER_STATE_DIR",
        "REAPER_RUNNER_DATABASE_URL",
        "REAPER_RUNNER_WORKSPACE_ID",
        "REAPER_RUNNER_TRUSTED_SCOPE_KEYS_JSON",
      ].includes(ref.toUpperCase()))
      throw new Error(
        "Attack job contains an invalid or reserved secret reference.",
      );
  return refs;
}

function childEnvironment(
  job: AttackJob,
  stateDirectory: string | undefined,
  durableState: { databaseUrl: string; workspaceId: string } | undefined,
  isolationMode: RunnerIsolationMode,
  trustedScopeConfig: string | undefined,
): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const name of ["SystemRoot", "WINDIR", "TEMP", "TMP"])
    if (process.env[name]) env[name] = process.env[name];
  if (stateDirectory)
    env.REAPER_RUNNER_STATE_DIR = path.resolve(stateDirectory);
  if (durableState) {
    env.REAPER_RUNNER_DATABASE_URL = durableState.databaseUrl;
    env.REAPER_RUNNER_WORKSPACE_ID = durableState.workspaceId;
  }
  env.REAPER_RUNNER_MODE = isolationMode;
  if (trustedScopeConfig) env[RUNNER_TRUST_ENV] = trustedScopeConfig;
  for (const ref of secretReferences(job.config))
    if (process.env[ref] !== undefined) {
      if (Buffer.byteLength(process.env[ref]!, "utf8") > 16_384)
        throw new Error("Configured runner secret exceeds the 16 KiB limit.");
      env[ref] = process.env[ref];
    }
  return env;
}

export async function runAttackJob(
  job: AttackJob,
  options: {
    signal?: AbortSignal;
    // Trusted caller configuration, never a field of AttackJob.
    trustedScopeConfig?: string;
    isolationMode?: RunnerIsolationMode;
    isolationProvider?: RunnerIsolationProvider;
    stateDirectory?: string;
    durableState?: {
      databaseUrl: string;
      workspaceId: string;
    };
  } = {},
): Promise<AttackJobOutcome> {
  const isolationMode = options.isolationMode ?? "standard";
  const isolationProvider =
    options.isolationProvider ?? new ProcessIsolationProvider();
  assertRunnerIsolation(isolationMode, isolationProvider);
  const stateDirectory = options.stateDirectory
    ? await ensureSecureDirectory(options.stateDirectory)
    : undefined;
  if (stateDirectory && options.durableState)
    throw new Error(
      "Runner state backend must be filesystem or PostgreSQL, not both.",
    );
  if (
    options.durableState &&
    (!options.durableState.databaseUrl ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
        options.durableState.workspaceId,
      ))
  )
    throw new Error("PostgreSQL runner state configuration is invalid.");
  if (isolationMode === "strict") {
    if (!stateDirectory && !options.durableState)
      throw new Error("Strict runner mode requires a durable state backend.");
    if (!job.workspaceId || !job.projectId)
      throw new Error("Strict runner mode requires workspaceId and projectId.");
    if (!job.scopeManifest || job.config.attack?.requireSignedScope !== true)
      throw new Error(
        "Strict runner mode requires a signed authorization scope.",
      );
  }

  const serializedJob = JSON.stringify(job);
  if (Buffer.byteLength(serializedJob, "utf8") > MAX_JOB_BYTES)
    throw new Error("Attack job exceeds the 5 MiB input limit.");
  const snapshot = JSON.parse(serializedJob) as AttackJob;
  assertJob(snapshot);
  const trustedScopeConfig = options.trustedScopeConfig;
  if (snapshot.scopeManifest) {
    const trust = parseRunnerTrustConfig(trustedScopeConfig ?? "");
    verifyAuthorizationScope(snapshot.scopeManifest, trust, {
      target: snapshot.target,
      environment: snapshot.authorization.environment,
      reference: snapshot.authorization.reference,
    });
  } else if (isolationMode === "strict") {
    throw new Error(
      "Strict runner requires independently provisioned signed-scope trust.",
    );
  }
  if (options.signal?.aborted)
    return { status: "INTERRUPTED", exitCode: null, reason: "cancelled" };

  const workingDirectory = await mkdtemp(path.join(tmpdir(), "reaper-run-"));
  let child: ChildProcess;
  try {
    child = isolationProvider.spawn({
      modulePath: JOB_FILE,
      cwd: workingDirectory,
      env: childEnvironment(
        snapshot,
        stateDirectory,
        options.durableState,
        isolationMode,
        snapshot.scopeManifest ? trustedScopeConfig : undefined,
      ),
      execArgv: [`--max-old-space-size=${snapshot.limits.memoryMb}`],
    });
  } catch {
    await rm(workingDirectory, { recursive: true, force: true });
    return { status: "FAILED", exitCode: null, reason: "spawn-failed" };
  }

  return await new Promise<AttackJobOutcome>((resolve) => {
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let oversizedOutput = false;
    let interruptedReason: string | undefined;
    let workerResult: string | undefined;
    let workerFailureReason = "worker-failed";
    let workerFailure = false;
    let cleanupTimer: NodeJS.Timeout | undefined;
    const cancelWorker = (reason: string): void => {
      if (interruptedReason || workerResult !== undefined) return;
      interruptedReason = reason;
      child.send({ type: "cancel" }, (error) => {
        if (error) child.kill("SIGKILL");
      });
      cleanupTimer = setTimeout(
        () => child.kill("SIGKILL"),
        snapshot.limits.cleanupGraceMs,
      );
    };
    const deadlineTimer = setTimeout(
      () => cancelWorker("deadline-exceeded"),
      Math.max(0, Date.parse(snapshot.deadline) - Date.now()),
    );
    const onAbort = (): void => cancelWorker("cancelled");
    options.signal?.addEventListener("abort", onAbort, { once: true });
    const countOutput = (chunk: Buffer, stream: "stdout" | "stderr"): void => {
      if (stream === "stdout") stdoutBytes += chunk.byteLength;
      else stderrBytes += chunk.byteLength;
      if (stdoutBytes > STDIO_LIMIT || stderrBytes > STDIO_LIMIT) {
        oversizedOutput = true;
        child.kill("SIGKILL");
      }
    };
    child.stdout?.on("data", (chunk: Buffer) => countOutput(chunk, "stdout"));
    child.stderr?.on("data", (chunk: Buffer) => countOutput(chunk, "stderr"));
    child.on("message", (message: unknown) => {
      if (!isRecord(message)) {
        workerFailure = true;
        child.kill("SIGKILL");
        return;
      }
      if (message.type === "result" && typeof message.json === "string")
        workerResult = message.json;
      else {
        workerFailure = true;
        if (message.type === "error" && typeof message.code === "string")
          workerFailureReason = message.code;
      }
    });
    child.on("error", () => {
      workerFailure = true;
    });
    child.on("close", async (code) => {
      clearTimeout(deadlineTimer);
      if (cleanupTimer) clearTimeout(cleanupTimer);
      options.signal?.removeEventListener("abort", onAbort);
      let outcome: AttackJobOutcome;
      if (interruptedReason) {
        let result: ScanResult | undefined;
        if (workerResult)
          try {
            result = JSON.parse(workerResult) as ScanResult;
          } catch {
            result = undefined;
          }
        outcome = {
          status: "INTERRUPTED",
          exitCode: code,
          reason: interruptedReason,
          ...(result ? { result } : {}),
        };
      } else if (oversizedOutput)
        outcome = { status: "FAILED", exitCode: code, reason: "stdio-limit" };
      else if (workerFailure || code !== 0 || workerResult === undefined)
        outcome = {
          status: "FAILED",
          exitCode: code,
          reason: workerFailureReason,
        };
      else {
        try {
          const bytes = Buffer.byteLength(workerResult, "utf8");
          if (bytes > snapshot.limits.maxOutputBytes)
            outcome = {
              status: "FAILED",
              exitCode: code,
              reason: "report-limit",
            };
          else
            outcome = {
              status: "COMPLETED",
              exitCode: 0,
              result: JSON.parse(workerResult) as ScanResult,
            };
        } catch {
          outcome = {
            status: "FAILED",
            exitCode: code,
            reason: "invalid-result",
          };
        }
      }
      try {
        await rm(workingDirectory, { recursive: true, force: true });
        resolve(outcome);
      } catch {
        resolve({
          status: "CLEANUP_FAILED",
          exitCode: code,
          reason: "temp-cleanup-failed",
        });
      }
    });
    child.send({ type: "job", json: serializedJob }, (error) => {
      if (error) {
        workerFailure = true;
        child.kill("SIGKILL");
      }
    });
    if (options.signal?.aborted) onAbort();
  });
}

export function createAttackJob(
  input: Omit<AttackJob, "version" | "runId" | "createdAt" | "deadline">,
): AttackJob {
  const createdAt = new Date();
  return {
    ...input,
    version: 1,
    runId: randomUUID(),
    createdAt: createdAt.toISOString(),
    deadline: new Date(
      createdAt.getTime() + input.limits.deadlineMs,
    ).toISOString(),
  };
}
