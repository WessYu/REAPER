import { randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { createApiKeyMaterial, requireRole } from "./auth.js";
import { resolveApiKeyExpiry } from "./api-key-expiry.js";
import { withWorkspaceContext } from "./db.js";
import type {
  CreateAssessmentInput,
  CreateProjectInput,
  CreateRunInput,
  IssuedApiKey,
  PlatformJob,
  RequestContext,
} from "./types.js";

function text(value: unknown, field: string, max = 200): string {
  if (
    typeof value !== "string" ||
    value.trim().length === 0 ||
    value.length > max
  )
    throw new Error(`${field} is invalid.`);
  return value.trim();
}

function uuid(value: unknown, field: string): string {
  const parsed = text(value, field, 64);
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      parsed,
    )
  )
    throw new Error(`${field} must be a UUID.`);
  return parsed;
}

function exactOrigin(value: unknown): string {
  const input = text(value, "targetOrigin", 2048);
  const parsed = new URL(input);
  if (
    !["http:", "https:"].includes(parsed.protocol) ||
    parsed.origin !== input ||
    parsed.username ||
    parsed.password
  )
    throw new Error("targetOrigin must be an exact HTTP(S) origin.");
  return parsed.origin;
}

function configPath(value: unknown): string {
  const input = text(value, "configPath", 1024);
  if (
    input.startsWith("/") ||
    input.includes("\\") ||
    input.split("/").some((part) => part === ".." || part === "")
  )
    throw new Error("configPath must be a normalized relative path.");
  return input;
}

function normalizedRun(input: CreateRunInput): CreateRunInput {
  const environments = new Set(["local", "preview", "staging", "production"]);
  if (!environments.has(input.environment))
    throw new Error("environment is invalid.");

  const allowedPermissions = new Set([
    "read",
    "mutations",
    "syntheticIdentities",
    "internalNetwork",
  ]);
  const permissions = input.permissions ?? ["read"];
  if (
    permissions.length < 1 ||
    permissions.length > 4 ||
    !permissions.includes("read") ||
    new Set(permissions).size !== permissions.length ||
    !permissions.every((permission) => allowedPermissions.has(permission))
  )
    throw new Error("permissions are invalid.");

  const limits = {
    maxRequests: input.limits?.maxRequests ?? 20,
    maxCleanupRequests: input.limits?.maxCleanupRequests ?? 10,
    rateLimitPerSecond: input.limits?.rateLimitPerSecond ?? 5,
    deadlineMs: input.limits?.deadlineMs ?? 120_000,
  };
  const bounds: Array<[keyof typeof limits, number, number]> = [
    ["maxRequests", 1, 500],
    ["maxCleanupRequests", 1, 200],
    ["rateLimitPerSecond", 1, 20],
    ["deadlineMs", 1_000, 30 * 60_000],
  ];
  for (const [name, minimum, maximum] of bounds) {
    const value = limits[name];
    if (!Number.isSafeInteger(value) || value < minimum || value > maximum)
      throw new Error(`${name} is outside the supported bounds.`);
  }

  return {
    projectId: uuid(input.projectId, "projectId"),
    assessmentId: uuid(input.assessmentId, "assessmentId"),
    targetOrigin: exactOrigin(input.targetOrigin),
    environment: input.environment,
    configPath: configPath(input.configPath),
    permissions,
    limits,
  };
}

export class PlatformRepository {
  constructor(
    private readonly pool: Pool,
    private readonly apiKeyPepper: string,
  ) {}

  async me(context: RequestContext): Promise<RequestContext> {
    return context;
  }

  async listProjects(context: RequestContext): Promise<unknown[]> {
    return withWorkspaceContext(this.pool, context, async (client) => {
      const result = await client.query(
        "SELECT id, name, created_at FROM reaper_control.projects ORDER BY created_at DESC LIMIT 200",
      );
      return result.rows;
    });
  }

  async createProject(
    context: RequestContext,
    input: CreateProjectInput,
  ): Promise<unknown> {
    requireRole(context, "analyst");
    return withWorkspaceContext(this.pool, context, async (client) => {
      const result = await client.query(
        "INSERT INTO reaper_control.projects(id,workspace_id,name) VALUES ($1,$2,$3) RETURNING id,name,created_at",
        [randomUUID(), context.workspaceId, text(input.name, "name")],
      );
      return result.rows[0];
    });
  }

  async listAssessments(context: RequestContext): Promise<unknown[]> {
    return withWorkspaceContext(this.pool, context, async (client) => {
      const result = await client.query(
        `SELECT id,project_id,reference,created_at
         FROM reaper_control.assessments
         ORDER BY created_at DESC LIMIT 500`,
      );
      return result.rows;
    });
  }

  async createAssessment(
    context: RequestContext,
    input: CreateAssessmentInput,
  ): Promise<unknown> {
    requireRole(context, "analyst");
    return withWorkspaceContext(this.pool, context, async (client) => {
      const result = await client.query(
        "INSERT INTO reaper_control.assessments(id,workspace_id,project_id,reference) VALUES ($1,$2,$3,$4) RETURNING id,project_id,reference,created_at",
        [
          randomUUID(),
          context.workspaceId,
          uuid(input.projectId, "projectId"),
          text(input.reference, "reference"),
        ],
      );
      return result.rows[0];
    });
  }

  async createRun(
    context: RequestContext,
    raw: CreateRunInput,
  ): Promise<unknown> {
    requireRole(context, "analyst");
    const input = normalizedRun(raw);
    return withWorkspaceContext(this.pool, context, async (client) => {
      await this.assertAssessmentProject(
        client,
        input.projectId,
        input.assessmentId,
      );
      const runId = randomUUID();
      const jobId = randomUUID();
      const run = await client.query(
        `INSERT INTO reaper_control.runs(
          id,workspace_id,project_id,assessment_id,status,target_origin,
          environment,config_path,permissions,limits
        ) VALUES ($1,$2,$3,$4,'PENDING',$5,$6,$7,$8::jsonb,$9::jsonb)
        RETURNING id,status,target_origin,environment,created_at,updated_at`,
        [
          runId,
          context.workspaceId,
          input.projectId,
          input.assessmentId,
          input.targetOrigin,
          input.environment,
          input.configPath,
          JSON.stringify(input.permissions),
          JSON.stringify(input.limits),
        ],
      );
      await client.query(
        `INSERT INTO reaper_control.jobs(
          id,workspace_id,run_id,status,payload
        ) VALUES ($1,$2,$3,'PENDING',$4::jsonb)`,
        [jobId, context.workspaceId, runId, JSON.stringify(input)],
      );
      return { ...run.rows[0], jobId };
    });
  }

  async listRuns(context: RequestContext): Promise<unknown[]> {
    return withWorkspaceContext(this.pool, context, async (client) => {
      const result = await client.query(
        `SELECT id,project_id,assessment_id,status,target_origin,environment,
                created_at,updated_at,error
         FROM reaper_control.runs
         ORDER BY created_at DESC LIMIT 500`,
      );
      return result.rows;
    });
  }

  async getRun(context: RequestContext, runId: string): Promise<unknown> {
    return withWorkspaceContext(this.pool, context, async (client) => {
      const result = await client.query(
        `SELECT id,project_id,assessment_id,status,target_origin,environment,
                permissions,limits,report,error,created_at,updated_at
         FROM reaper_control.runs WHERE id=$1`,
        [uuid(runId, "runId")],
      );
      if (!result.rows[0]) throw new Error("Run not found.");
      return result.rows[0];
    });
  }

  async listFindings(
    context: RequestContext,
    runId: string,
  ): Promise<unknown[]> {
    return withWorkspaceContext(this.pool, context, async (client) => {
      const result = await client.query(
        `SELECT id,rule_id,severity,payload,created_at
         FROM reaper_control.findings
         WHERE run_id=$1 ORDER BY created_at,id LIMIT 2000`,
        [uuid(runId, "runId")],
      );
      return result.rows;
    });
  }

  async listAudit(context: RequestContext, runId: string): Promise<unknown[]> {
    return withWorkspaceContext(this.pool, context, async (client) => {
      const result = await client.query(
        `SELECT sequence,previous_hash,event_hash,event_type,payload,created_at
         FROM reaper_control.audit_events
         WHERE run_id=$1 ORDER BY sequence LIMIT 5000`,
        [uuid(runId, "runId")],
      );
      return result.rows;
    });
  }

  async listApiKeys(context: RequestContext): Promise<unknown[]> {
    requireRole(context, "admin");
    return withWorkspaceContext(this.pool, context, async (client) => {
      const result = await client.query(
        `SELECT id,principal_id,name,expires_at,revoked_at,created_at,last_used_at
         FROM reaper_control.api_keys
         ORDER BY created_at DESC LIMIT 200`,
      );
      return result.rows;
    });
  }

  async createApiKey(
    context: RequestContext,
    input: { principalId?: string; name: string; expiresAt?: string | null },
  ): Promise<IssuedApiKey> {
    requireRole(context, "admin");
    const principalId = text(
      input.principalId ?? context.principalId,
      "principalId",
    );
    const expiresAt = resolveApiKeyExpiry(input.expiresAt);

    const material = createApiKeyMaterial(this.apiKeyPepper, expiresAt);
    await withWorkspaceContext(this.pool, context, async (client) => {
      await client.query(
        "SELECT reaper_control.create_api_key($1,$2,$3,$4,$5)",
        [
          material.id,
          principalId,
          text(input.name, "name"),
          material.secretHash,
          material.expiresAt,
        ],
      );
    });
    return {
      id: material.id,
      token: material.token,
      expiresAt: material.expiresAt,
    };
  }

  async revokeApiKey(context: RequestContext, keyId: string): Promise<boolean> {
    requireRole(context, "admin");
    return withWorkspaceContext(this.pool, context, async (client) => {
      const result = await client.query<{ revoked: boolean }>(
        "SELECT reaper_control.revoke_api_key($1::uuid) AS revoked",
        [uuid(keyId, "keyId")],
      );
      return result.rows[0]?.revoked === true;
    });
  }

  async leaseJob(
    workerId: string,
    leaseSeconds = 120,
  ): Promise<PlatformJob | null> {
    const result = await this.pool.query<{
      id: string;
      workspace_id: string;
      run_id: string;
      attempt: number;
      payload: CreateRunInput;
      lease_expires_at: Date;
    }>("SELECT * FROM reaper_control.lease_platform_job($1,$2)", [
      text(workerId, "workerId"),
      leaseSeconds,
    ]);
    const row = result.rows[0];
    if (!row) return null;
    return {
      id: row.id,
      workspaceId: row.workspace_id,
      runId: row.run_id,
      status: "RUNNING",
      attempt: row.attempt,
      availableAt: new Date().toISOString(),
      leaseExpiresAt: row.lease_expires_at.toISOString(),
      payload: row.payload,
    };
  }

  async prepareExecutionEnvelope(
    job: PlatformJob,
    workerId: string,
    envelope: unknown,
    expiresAt: string,
  ): Promise<void> {
    if (
      !Number.isFinite(Date.parse(expiresAt)) ||
      Date.parse(expiresAt) <= Date.now()
    )
      throw new Error("Execution envelope expiry is invalid.");
    const result = await this.pool.query<{ prepared: boolean }>(
      "SELECT reaper_control.prepare_platform_execution_envelope($1,$2,$3::jsonb,$4::timestamptz) AS prepared",
      [job.id, text(workerId, "workerId"), JSON.stringify(envelope), expiresAt],
    );
    if (result.rows[0]?.prepared !== true)
      throw new Error("Job lease was lost before execution preparation.");
  }

  async completeJob(
    job: PlatformJob,
    workerId: string,
    report: unknown,
  ): Promise<void> {
    const result = await this.pool.query<{ completed: boolean }>(
      "SELECT reaper_control.complete_platform_job($1,$2,$3::jsonb) AS completed",
      [job.id, workerId, JSON.stringify(report)],
    );
    if (result.rows[0]?.completed !== true)
      throw new Error("Job lease was lost before completion.");
  }

  async failJob(
    job: PlatformJob,
    workerId: string,
    error: unknown,
    retryDelaySeconds: number,
  ): Promise<void> {
    const message =
      error instanceof Error ? error.message : "Platform worker failed.";
    const result = await this.pool.query<{ failed: boolean }>(
      "SELECT reaper_control.fail_platform_job($1,$2,$3,$4) AS failed",
      [job.id, workerId, message, retryDelaySeconds],
    );
    if (result.rows[0]?.failed !== true)
      throw new Error("Job lease was lost before failure could be recorded.");
  }

  private async assertAssessmentProject(
    client: PoolClient,
    projectId: string,
    assessmentId: string,
  ): Promise<void> {
    const result = await client.query(
      `SELECT 1 FROM reaper_control.assessments
       WHERE id=$1 AND project_id=$2`,
      [assessmentId, projectId],
    );
    if (!result.rows[0])
      throw new Error("Assessment does not belong to the selected project.");
  }
}
