import {
  parseRunnerBearer,
  verifyGitHubRunnerToken,
} from "./github-oidc.mjs";

const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SEVERITIES = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]);
const GENESIS = "0".repeat(64);

function canonical(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean")
    return JSON.stringify(value);
  if (typeof value === "number" && Number.isFinite(value))
    return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (!value || typeof value !== "object")
    throw new Error("Audit payload contains a non-JSON value.");
  const record = value as Record<string, unknown>;
  return (
    "{" +
    Object.keys(record)
      .sort()
      .map((key) => JSON.stringify(key) + ":" + canonical(record[key]))
      .join(",") +
    "}"
  );
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function readRunnerBody(
  request: Request,
): Promise<Record<string, unknown>> {
  const contentType = request.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().startsWith("application/json"))
    throw new Error("Runner Content-Type must be application/json.");
  const raw = await request.text();
  if (new TextEncoder().encode(raw).byteLength > 512 * 1024)
    throw new Error("Runner request body exceeds 512 KiB.");
  const value = raw ? JSON.parse(raw) : {};
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("Runner request body must be a JSON object.");
  return value as Record<string, unknown>;
}

function jobId(value: unknown): string {
  if (typeof value !== "string" || !UUID.test(value))
    throw new Error("Runner jobId is invalid.");
  return value;
}

function safeError(value: unknown): string {
  if (typeof value !== "string") return "free runner failed";
  const cleaned = value.replace(/[\u0000-\u001f\u007f]/g, " ").trim();
  return cleaned.slice(0, 500) || "free runner failed";
}

function validateFreePayload(payload: unknown): asserts payload is {
  projectId: string;
  assessmentId: string;
  targetOrigin: string;
  environment: "preview" | "staging";
  configPath: "free-readonly.ts";
  permissions: ["read"];
  limits: {
    maxRequests: number;
    maxCleanupRequests: number;
    rateLimitPerSecond: number;
    deadlineMs: number;
  };
} {
  if (!payload || typeof payload !== "object" || Array.isArray(payload))
    throw new Error("Free runner payload is invalid.");
  const value = payload as Record<string, unknown>;
  const target =
    typeof value.targetOrigin === "string"
      ? new URL(value.targetOrigin)
      : undefined;
  const permissions = value.permissions;
  const limits =
    value.limits &&
    typeof value.limits === "object" &&
    !Array.isArray(value.limits)
      ? (value.limits as Record<string, unknown>)
      : {};
  if (
    typeof value.projectId !== "string" ||
    !UUID.test(value.projectId) ||
    typeof value.assessmentId !== "string" ||
    !UUID.test(value.assessmentId) ||
    !target ||
    target.protocol !== "https:" ||
    target.origin !== value.targetOrigin ||
    target.username ||
    target.password ||
    !["preview", "staging"].includes(String(value.environment)) ||
    value.configPath !== "free-readonly.ts" ||
    !Array.isArray(permissions) ||
    permissions.length !== 1 ||
    permissions[0] !== "read" ||
    !Number.isSafeInteger(limits.maxRequests) ||
    Number(limits.maxRequests) < 1 ||
    Number(limits.maxRequests) > 8 ||
    !Number.isSafeInteger(limits.maxCleanupRequests) ||
    Number(limits.maxCleanupRequests) < 0 ||
    Number(limits.maxCleanupRequests) > 1 ||
    !Number.isSafeInteger(limits.rateLimitPerSecond) ||
    Number(limits.rateLimitPerSecond) < 1 ||
    Number(limits.rateLimitPerSecond) > 2 ||
    !Number.isSafeInteger(limits.deadlineMs) ||
    Number(limits.deadlineMs) < 1000 ||
    Number(limits.deadlineMs) > 60000
  )
    throw new Error("Free runner job escaped the read-only safety profile.");
}

async function activeJob(tx: any, id: string, workerId: string) {
  const rows = await tx.unsafe(
    "SELECT workspace_id,run_id,payload FROM reaper_control.jobs " +
      "WHERE id=$1::uuid AND status='RUNNING' AND worker_id=$2 " +
      "AND lease_expires_at > now() FOR UPDATE",
    [id, workerId],
  );
  const row = rows[0];
  if (!row) throw new Error("Free runner lease is unavailable or expired.");
  validateFreePayload(row.payload);
  return row;
}

async function appendAudit(
  tx: any,
  workspaceId: string,
  runId: string,
  type: string,
  data: Record<string, unknown>,
): Promise<void> {
  await tx.unsafe(
    "SELECT id FROM reaper_control.runs " +
      "WHERE workspace_id=$1::uuid AND id=$2::uuid FOR UPDATE",
    [workspaceId, runId],
  );
  const last = await tx.unsafe(
    "SELECT sequence,event_hash FROM reaper_control.audit_events " +
      "WHERE workspace_id=$1::uuid AND run_id=$2::uuid " +
      "ORDER BY sequence DESC LIMIT 1",
    [workspaceId, runId],
  );
  const sequence = last[0] ? Number(last[0].sequence) + 1 : 1;
  if (!Number.isSafeInteger(sequence) || sequence > 5000)
    throw new Error("Free runner audit trail exceeds its event limit.");
  const previousHash = last[0]?.event_hash ?? GENESIS;
  const at = new Date().toISOString();
  const base = {
    version: 1,
    runId,
    sequence,
    previousHash,
    type,
    at,
    data,
  };
  const eventHash = await sha256(canonical(base));
  await tx.unsafe(
    "INSERT INTO reaper_control.audit_events(" +
      "workspace_id,run_id,sequence,previous_hash,event_hash,event_type,payload,created_at" +
      ") VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6,$7::jsonb,$8::timestamptz)",
    [
      workspaceId,
      runId,
      sequence,
      previousHash,
      eventHash,
      type,
      JSON.stringify(data),
      at,
    ],
  );
  await tx.unsafe(
    "INSERT INTO reaper_control.audit_heads(" +
      "workspace_id,run_id,sequence,event_hash,updated_at" +
      ") VALUES ($1::uuid,$2::uuid,$3,$4,now()) " +
      "ON CONFLICT (workspace_id,run_id) DO UPDATE SET " +
      "sequence=EXCLUDED.sequence,event_hash=EXCLUDED.event_hash,updated_at=now()",
    [workspaceId, runId, sequence, eventHash],
  );
}

async function normalizeFindings(
  tx: any,
  workspaceId: string,
  runId: string,
  report: Record<string, unknown>,
): Promise<number> {
  const findings = Array.isArray(report.findings)
    ? report.findings.slice(0, 200)
    : [];
  let inserted = 0;
  for (const raw of findings) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) continue;
    const finding = raw as Record<string, unknown>;
    if (
      typeof finding.ruleId !== "string" ||
      finding.ruleId.length < 1 ||
      finding.ruleId.length > 200 ||
      typeof finding.severity !== "string" ||
      !SEVERITIES.has(finding.severity)
    )
      continue;
    const serialized = JSON.stringify(finding);
    if (new TextEncoder().encode(serialized).byteLength > 32 * 1024) continue;
    await tx.unsafe(
      "INSERT INTO reaper_control.findings(" +
        "id,workspace_id,run_id,rule_id,severity,payload" +
        ") VALUES ($1::uuid,$2::uuid,$3::uuid,$4,$5,$6::jsonb)",
      [
        crypto.randomUUID(),
        workspaceId,
        runId,
        finding.ruleId,
        finding.severity,
        serialized,
      ],
    );
    inserted += 1;
  }
  return inserted;
}

export async function handleFreeRunnerRequest(input: {
  request: Request;
  path: string;
  method: string;
  sql: any;
  json: (status: number, value: unknown) => Response;
}): Promise<Response> {
  const { request, path, method, sql, json } = input;
  const token = parseRunnerBearer(request);
  const identity = await verifyGitHubRunnerToken(token);

  if (method === "POST" && path === "/runner/lease") {
    return await sql.begin(async (tx: any) => {
      const rows = await tx.unsafe(
        "SELECT * FROM reaper_control.lease_free_platform_job($1,300)",
        [identity.workerId],
      );
      const row = rows[0];
      if (!row) return json(200, { job: null });
      validateFreePayload(row.payload);
      await appendAudit(
        tx,
        row.workspace_id,
        row.run_id,
        "FREE_RUNNER_LEASED",
        {
          provider: "github-actions",
          githubRunId: identity.runId,
          githubRunAttempt: identity.runAttempt,
          actor: identity.actor,
        },
      );
      return json(200, {
        job: {
          id: row.id,
          workspaceId: row.workspace_id,
          runId: row.run_id,
          attempt: Number(row.attempt),
          workerId: identity.workerId,
          payload: row.payload,
          leaseExpiresAt: new Date(row.lease_expires_at).toISOString(),
        },
      });
    });
  }

  if (method === "POST" && path === "/runner/heartbeat") {
    const body = await readRunnerBody(request);
    const id = jobId(body.jobId);
    return await sql.begin(async (tx: any) => {
      await activeJob(tx, id, identity.workerId);
      const rows = await tx.unsafe(
        "SELECT reaper_control.renew_platform_job_lease($1::uuid,$2,300) AS renewed",
        [id, identity.workerId],
      );
      if (rows[0]?.renewed !== true)
        throw new Error("Free runner lease renewal failed.");
      return json(200, { renewed: true });
    });
  }

  if (method === "POST" && path === "/runner/complete") {
    const body = await readRunnerBody(request);
    const id = jobId(body.jobId);
    if (
      !body.report ||
      typeof body.report !== "object" ||
      Array.isArray(body.report)
    )
      throw new Error("Free runner report is invalid.");
    const report = body.report as Record<string, unknown>;
    return await sql.begin(async (tx: any) => {
      const job = await activeJob(tx, id, identity.workerId);
      const findingCount = await normalizeFindings(
        tx,
        job.workspace_id,
        job.run_id,
        report,
      );
      await appendAudit(
        tx,
        job.workspace_id,
        job.run_id,
        "FREE_RUNNER_COMPLETED",
        {
          provider: "github-actions",
          githubRunId: identity.runId,
          githubRunAttempt: identity.runAttempt,
          normalizedFindings: findingCount,
        },
      );
      const rows = await tx.unsafe(
        "SELECT reaper_control.complete_platform_job($1::uuid,$2,$3::jsonb) AS completed",
        [id, identity.workerId, JSON.stringify(report)],
      );
      if (rows[0]?.completed !== true)
        throw new Error("Free runner completion lost its lease.");
      return json(200, { completed: true, findings: findingCount });
    });
  }

  if (method === "POST" && path === "/runner/fail") {
    const body = await readRunnerBody(request);
    const id = jobId(body.jobId);
    const message = safeError(body.error);
    return await sql.begin(async (tx: any) => {
      const job = await activeJob(tx, id, identity.workerId);
      await appendAudit(
        tx,
        job.workspace_id,
        job.run_id,
        "FREE_RUNNER_FAILED",
        {
          provider: "github-actions",
          githubRunId: identity.runId,
          githubRunAttempt: identity.runAttempt,
          reason: message,
        },
      );
      const rows = await tx.unsafe(
        "SELECT reaper_control.fail_platform_job($1::uuid,$2,$3,30) AS failed",
        [id, identity.workerId, message],
      );
      if (rows[0]?.failed !== true)
        throw new Error("Free runner failure could not be persisted.");
      return json(200, { failed: true });
    });
  }

  return json(404, { error: "Runner route not found." });
}
