import { randomUUID } from "node:crypto";
import path from "node:path";
import { createPlatformPool } from "./db.js";
import { PlatformRepository } from "./repository.js";
import { buildScopePayload } from "./scope-signer.js";
import { GcpKmsScopeSigner } from "./gcp-kms-signer.js";
import { CloudRunJobClient } from "./cloud-run-job.js";
import type { PlatformJob } from "./types.js";

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required.`);
  return value;
}

function safeConfigFile(root: string, relative: string): string {
  if (
    relative.startsWith("/") ||
    relative.includes("\\") ||
    relative.split("/").some((part) => !part || part === "..")
  )
    throw new Error("Cloud dispatcher config path is unsafe.");
  const resolvedRoot = path.resolve(root);
  const resolved = path.resolve(resolvedRoot, relative);
  if (!resolved.startsWith(resolvedRoot + path.sep))
    throw new Error("Cloud dispatcher config escaped its trusted root.");
  return resolved;
}

function encodeEnvelope(value: unknown): string {
  const json = JSON.stringify(value);
  if (Buffer.byteLength(json, "utf8") > 650_000)
    throw new Error("Cloud Run execution envelope is too large.");
  return Buffer.from(json, "utf8").toString("base64url");
}

async function buildAttackJob(job: PlatformJob, workerId: string): Promise<unknown> {
  const rootDist = new URL("../../dist/", import.meta.url);
  const configModule = (await import(new URL("config.js", rootDist).href)) as {
    readConfig: (file: string) => Promise<Record<string, unknown>>;
  };
  const model = (await import(new URL("model.js", rootDist).href)) as {
    ENGINE_VERSION: string;
  };

  const permissions = job.payload.permissions ?? ["read"];
  const limits = {
    maxRequests: job.payload.limits?.maxRequests ?? 20,
    maxCleanupRequests: job.payload.limits?.maxCleanupRequests ?? 10,
    rateLimitPerSecond: job.payload.limits?.rateLimitPerSecond ?? 5,
    deadlineMs: job.payload.limits?.deadlineMs ?? 120_000,
  };
  const signer = await GcpKmsScopeSigner.create({
    keyVersionName: required("REAPER_GCP_KMS_KEY_VERSION"),
    keyId: required("REAPER_GCP_KMS_KEY_ID"),
  });
  const scopePayload = buildScopePayload({
    runId: job.runId,
    assessmentId: job.payload.assessmentId,
    workspaceId: job.workspaceId,
    target: job.payload.targetOrigin,
    environment: job.payload.environment,
    permissions,
    limits,
  });
  const scope = await signer.sign(scopePayload);

  const configFile = safeConfigFile(
    required("REAPER_PLATFORM_CONFIG_ROOT"),
    job.payload.configPath,
  );
  const base = await configModule.readConfig(configFile);
  const baseAttack =
    base.attack && typeof base.attack === "object"
      ? (base.attack as Record<string, unknown>)
      : {};
  const authorization =
    baseAttack.authorization && typeof baseAttack.authorization === "object"
      ? (baseAttack.authorization as Record<string, unknown>)
      : {};
  const config = {
    ...base,
    attack: {
      ...baseAttack,
      allowedTargets: [job.payload.targetOrigin],
      requireSignedScope: true,
      authorization: {
        ...authorization,
        acknowledged: true,
        reference: job.payload.assessmentId,
        environment: job.payload.environment,
        expiresAt: scope.payload.expiresAt,
      },
      maxRequests: limits.maxRequests,
      maxCleanupRequests: limits.maxCleanupRequests,
      rateLimitPerSecond: limits.rateLimitPerSecond,
    },
  };

  const now = new Date();
  return {
    version: 1,
    runId: job.runId,
    target: job.payload.targetOrigin,
    authorization: {
      reference: job.payload.assessmentId,
      environment: job.payload.environment,
      expiresAt: scope.payload.expiresAt,
    },
    config,
    limits: {
      deadlineMs: limits.deadlineMs,
      cleanupGraceMs: Math.min(
        60_000,
        Math.max(5_000, Math.floor(limits.deadlineMs / 10)),
      ),
      memoryMb: 384,
      maxOutputBytes: 8 * 1024 * 1024,
    },
    engineVersion: model.ENGINE_VERSION,
    createdAt: now.toISOString(),
    deadline: new Date(now.getTime() + limits.deadlineMs).toISOString(),
    workspaceId: job.workspaceId,
    projectId: job.payload.projectId,
    scopeManifest: scope,
    trustedScopeKeys: { [scope.keyId]: signer.publicKeyPem },
    platform: {
      jobId: job.id,
      workerId,
    },
  };
}

async function main(): Promise<void> {
  const pool = createPlatformPool(required("REAPER_PLATFORM_DATABASE_URL"));
  const repository = new PlatformRepository(
    pool,
    process.env.REAPER_PLATFORM_API_KEY_PEPPER ?? "dispatcher-does-not-use-api-keys-00000000",
  );
  const workerId =
    process.env.REAPER_PLATFORM_WORKER_ID ?? `cloud-dispatcher-${randomUUID()}`;

  try {
    const job = await repository.leaseJob(workerId, 900);
    if (!job) return;
    try {
      const attackJob = await buildAttackJob(job, workerId);
      const client = new CloudRunJobClient({
        projectId: required("REAPER_GCP_PROJECT_ID"),
        region: required("REAPER_GCP_REGION"),
        jobName: required("REAPER_GCP_RUNNER_JOB"),
      });
      const execution = await client.execute({
        executionEnvelope: encodeEnvelope(attackJob),
        timeoutMs: job.payload.limits?.deadlineMs ?? 120_000,
      });
      console.log(
        JSON.stringify({
          event: "reaper.cloud-run.dispatched",
          runId: job.runId,
          jobId: job.id,
          operation: execution.operationName,
        }),
      );
    } catch (error) {
      await repository.failJob(
        job,
        workerId,
        error,
        job.attempt < 3 ? Math.min(300, 15 * 2 ** (job.attempt - 1)) : 0,
      );
      throw error;
    }
  } finally {
    await pool.end();
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : "cloud dispatcher failed");
  process.exitCode = 2;
});
