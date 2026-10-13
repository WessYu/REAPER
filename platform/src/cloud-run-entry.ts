import { fork, type ChildProcess } from "node:child_process";
import { Pool } from "pg";

interface ExecutionEnvelope {
  version: 1;
  runId: string;
  workspaceId: string;
  limits: { deadlineMs: number };
  platform: { jobId: string; workerId: string };
}

class CloudRunIsolationProvider {
  readonly name = "google-cloud-run-job";
  readonly capabilities = {
    processIsolation: true,
    filesystemIsolation: true,
    networkIsolation: process.env.REAPER_CLOUD_RUN_NETWORK_ENFORCED === "1",
    resourceLimits: process.env.REAPER_CLOUD_RUN_RESOURCE_ENFORCED === "1",
  };

  spawn(input: {
    modulePath: string;
    cwd: string;
    env: NodeJS.ProcessEnv;
    execArgv: string[];
  }): ChildProcess {
    if (!process.env.CLOUD_RUN_JOB || !process.env.CLOUD_RUN_EXECUTION)
      throw new Error("Cloud Run job execution identity is unavailable.");
    if (!this.capabilities.networkIsolation || !this.capabilities.resourceLimits)
      throw new Error("Cloud Run strict isolation attestations are incomplete.");
    return fork(input.modulePath, [], {
      cwd: input.cwd,
      env: input.env,
      execArgv: input.execArgv,
      stdio: ["ignore", "pipe", "pipe", "ipc"],
      serialization: "json",
    });
  }
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required.`);
  return value;
}

function decodeEnvelope(): ExecutionEnvelope & Record<string, unknown> {
  const encoded = required("REAPER_EXECUTION_ENVELOPE_B64");
  if (
    !/^[A-Za-z0-9_-]+$/.test(encoded) ||
    Buffer.byteLength(encoded, "utf8") > 900_000
  )
    throw new Error("Cloud Run execution envelope is invalid.");
  const raw = Buffer.from(encoded, "base64url").toString("utf8");
  const value = JSON.parse(raw) as ExecutionEnvelope & Record<string, unknown>;
  if (
    value.version !== 1 ||
    typeof value.runId !== "string" ||
    typeof value.workspaceId !== "string" ||
    !value.platform ||
    typeof value.platform.jobId !== "string" ||
    typeof value.platform.workerId !== "string"
  )
    throw new Error("Cloud Run execution envelope metadata is invalid.");
  return value;
}

async function main(): Promise<void> {
  const databaseUrl = required("REAPER_PLATFORM_DATABASE_URL");
  const envelope = decodeEnvelope();
  const rootDist = new URL("../../dist/", import.meta.url);
  const engine = (await import(new URL("index.js", rootDist).href)) as {
    runAttackJob: (
      job: unknown,
      options: unknown,
    ) => Promise<{
      status: string;
      reason?: string;
      result?: unknown;
    }>;
  };

  const pool = new Pool({
    connectionString: databaseUrl,
    max: 1,
    application_name: "reaper-cloud-runner",
  });
  let heartbeatFailure: Error | undefined;
  const renew = async (): Promise<void> => {
    const result = await pool.query<{ renewed: boolean }>(
      "SELECT reaper_control.renew_platform_job_lease($1,$2,900) AS renewed",
      [envelope.platform.jobId, envelope.platform.workerId],
    );
    if (result.rows[0]?.renewed !== true)
      throw new Error("Cloud Run job lease could not be renewed.");
  };
  const timer = setInterval(() => {
    void renew().catch((error: unknown) => {
      heartbeatFailure =
        error instanceof Error ? error : new Error("job lease heartbeat failed");
    });
  }, 5 * 60_000);
  timer.unref();

  try {
    await renew();
    const { platform: _platform, ...attackJob } = envelope;
    void _platform;
    const outcome = await engine.runAttackJob(attackJob, {
      isolationMode: "strict",
      isolationProvider: new CloudRunIsolationProvider(),
      durableState: {
        databaseUrl,
        workspaceId: envelope.workspaceId,
      },
    });
    if (heartbeatFailure) throw heartbeatFailure;

    if (outcome.status === "COMPLETED") {
      const result = await pool.query<{ completed: boolean }>(
        "SELECT reaper_control.complete_platform_job($1,$2,$3::jsonb) AS completed",
        [
          envelope.platform.jobId,
          envelope.platform.workerId,
          JSON.stringify(outcome.result ?? outcome),
        ],
      );
      if (result.rows[0]?.completed !== true)
        throw new Error("Cloud Run completion lost its durable job lease.");
      return;
    }

    const failed = await pool.query<{ failed: boolean }>(
      "SELECT reaper_control.fail_platform_job($1,$2,$3,0) AS failed",
      [
        envelope.platform.jobId,
        envelope.platform.workerId,
        outcome.reason ?? outcome.status,
      ],
    );
    if (failed.rows[0]?.failed !== true)
      throw new Error("Cloud Run failure could not be persisted.");
    process.exitCode = 2;
  } catch (error) {
    await pool
      .query(
        "SELECT reaper_control.fail_platform_job($1,$2,$3,0) AS failed",
        [
          envelope.platform.jobId,
          envelope.platform.workerId,
          error instanceof Error ? error.message : "cloud runner failed",
        ],
      )
      .catch(() => {});
    throw error;
  } finally {
    clearInterval(timer);
    await pool.end();
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : "cloud runner failed");
  process.exitCode = 2;
});
