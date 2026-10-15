import { fork, type ChildProcess } from "node:child_process";
import { Pool } from "pg";
import { readFile } from "node:fs/promises";

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
    if (
      !this.capabilities.networkIsolation ||
      !this.capabilities.resourceLimits
    )
      throw new Error(
        "Cloud Run strict isolation attestations are incomplete.",
      );
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

async function main(): Promise<void> {
  const databaseUrl = required("REAPER_PLATFORM_DATABASE_URL");
  const jobId = required("REAPER_EXECUTION_JOB_ID");
  const workerId = required("REAPER_EXECUTION_WORKER_ID");
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      jobId,
    ) ||
    !/^[A-Za-z0-9._:-]{1,200}$/.test(workerId)
  )
    throw new Error("Cloud Run execution identity is invalid.");
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
  let envelope: ExecutionEnvelope & Record<string, unknown>;
  try {
    const loaded = await pool.query<{
      workspace_id: string;
      run_id: string;
      envelope: ExecutionEnvelope & Record<string, unknown>;
    }>("SELECT * FROM reaper_control.load_platform_execution_envelope($1,$2)", [
      jobId,
      workerId,
    ]);
    const row = loaded.rows[0];
    if (!row)
      throw new Error(
        "Cloud Run execution envelope is unavailable or expired.",
      );
    envelope = row.envelope;
    if (
      envelope.version !== 1 ||
      envelope.runId !== row.run_id ||
      envelope.workspaceId !== row.workspace_id ||
      envelope.platform?.jobId !== jobId ||
      envelope.platform?.workerId !== workerId
    )
      throw new Error("Cloud Run execution envelope metadata is inconsistent.");
  } catch (error) {
    await pool.end().catch(() => {});
    throw error;
  }

  let heartbeatFailure: Error | undefined;
  const renew = async (): Promise<void> => {
    const result = await pool.query<{ renewed: boolean }>(
      "SELECT reaper_control.renew_platform_job_lease($1,$2,900) AS renewed",
      [jobId, workerId],
    );
    if (result.rows[0]?.renewed !== true)
      throw new Error("Cloud Run job lease could not be renewed.");
  };
  const timer = setInterval(() => {
    void renew().catch((error: unknown) => {
      heartbeatFailure =
        error instanceof Error
          ? error
          : new Error("job lease heartbeat failed");
    });
  }, 5 * 60_000);
  timer.unref();

  try {
    await renew();
    const { platform: _platform, ...attackJob } = envelope;
    void _platform;
    // This fixed Secret Manager volume path is part of the runner image/config.
    // Cloud Run job execution overrides cannot replace mounted secret volumes.
    const trustedScopeConfig = await readFile(
      "/var/run/reaper-trust/trusted-scope-keys.json",
      "utf8",
    );
    const outcome = await engine.runAttackJob(attackJob, {
      trustedScopeConfig,
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
        [jobId, workerId, JSON.stringify(outcome.result ?? outcome)],
      );
      if (result.rows[0]?.completed !== true)
        throw new Error("Cloud Run completion lost its durable job lease.");
      await pool.query(
        "SELECT reaper_control.delete_platform_execution_envelope($1,$2)",
        [jobId, workerId],
      );
      return;
    }

    const failed = await pool.query<{ failed: boolean }>(
      "SELECT reaper_control.fail_platform_job($1,$2,$3,0) AS failed",
      [jobId, workerId, outcome.reason ?? outcome.status],
    );
    if (failed.rows[0]?.failed !== true)
      throw new Error("Cloud Run failure could not be persisted.");
    await pool.query(
      "SELECT reaper_control.delete_platform_execution_envelope($1,$2)",
      [jobId, workerId],
    );
    process.exitCode = 2;
  } catch (error) {
    await pool
      .query("SELECT reaper_control.fail_platform_job($1,$2,$3,0) AS failed", [
        jobId,
        workerId,
        error instanceof Error ? error.message : "cloud runner failed",
      ])
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
