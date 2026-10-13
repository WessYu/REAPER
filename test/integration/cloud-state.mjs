import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import pg from "pg";
import {
  PostgresExecutionJournalStore,
  PostgresScopeReplayStore,
  PostgresAuditStore,
} from "../../dist/postgres-state.js";

const connectionString = process.env.REAPER_TEST_DATABASE_URL;
if (!connectionString)
  throw new Error(
    "Set REAPER_TEST_DATABASE_URL to a disposable PostgreSQL database.",
  );

const migrations = await Promise.all(
  [1, 2, 3, 4].map(async (number) => {
    const names = {
      1: "001_init.sql",
      2: "002_platform.sql",
      3: "003_staging_hardening.sql",
      4: "004_cloud_run.sql",
    };
    return readFile(
      fileURLToPath(
        new URL(`../../control-plane/${names[number]}`, import.meta.url),
      ),
      "utf8",
    );
  }),
);

test("PostgreSQL strict-runner state survives independent store instances", async () => {
  const admin = new pg.Pool({ connectionString, max: 2 });
  const ids = {
    org: "20000000-0000-4000-8000-000000000001",
    workspace: "20000000-0000-4000-8000-000000000002",
    project: "20000000-0000-4000-8000-000000000003",
    assessment: "20000000-0000-4000-8000-000000000004",
    run: "20000000-0000-4000-8000-000000000005",
    key: "20000000-0000-4000-8000-000000000006",
  };

  try {
    await admin.query("DROP SCHEMA IF EXISTS reaper_control CASCADE");
    for (const migration of migrations) await admin.query(migration);
    await admin.query(
      "SELECT reaper_control.bootstrap_platform($1,$2,$3,$4,$5,$6,$7,$8,NULL)",
      [
        ids.org,
        "Cloud State Org",
        ids.workspace,
        "Cloud State",
        "owner",
        ids.key,
        "bootstrap",
        "a".repeat(64),
      ],
    );
    await admin.query("BEGIN");
    await admin.query(
      "SELECT set_config('reaper.workspace_id',$1,true),set_config('reaper.principal_id','owner',true)",
      [ids.workspace],
    );
    await admin.query(
      "INSERT INTO reaper_control.projects(id,workspace_id,name) VALUES ($1,$2,'Project')",
      [ids.project, ids.workspace],
    );
    await admin.query(
      "INSERT INTO reaper_control.assessments(id,workspace_id,project_id,reference) VALUES ($1,$2,$3,'assessment')",
      [ids.assessment, ids.workspace, ids.project],
    );
    await admin.query(
      "INSERT INTO reaper_control.runs(id,workspace_id,project_id,assessment_id,status,target_origin,environment,config_path) VALUES ($1,$2,$3,$4,'RUNNING','https://preview.example.test','staging','cloud-run-readonly.ts')",
      [ids.run, ids.workspace, ids.project, ids.assessment],
    );
    await admin.query("COMMIT");

    const journal = new PostgresExecutionJournalStore(admin, ids.workspace);
    const created = await journal.create({
      version: 1,
      runId: ids.run,
      workspaceId: ids.workspace,
      projectId: ids.project,
      assessmentId: ids.assessment,
      targetOrigin: "https://preview.example.test",
      environment: "staging",
      allowPrivateNetwork: false,
      timeoutMs: 5000,
      rateLimitPerSecond: 2,
      maxCleanupRequests: 10,
      createdAt: new Date().toISOString(),
      status: "RUNNING",
    });
    assert.equal(created.status, "RUNNING");
    await journal.update(ids.run, (record) => {
      record.status = "CLEANING";
    });
    const restartedJournal = new PostgresExecutionJournalStore(
      admin,
      ids.workspace,
    );
    assert.equal((await restartedJournal.read(ids.run)).status, "CLEANING");

    const replay = new PostgresScopeReplayStore(admin, ids.workspace);
    const nonce = {
      issuer: "reaper-platform",
      assessmentId: ids.assessment,
      nonce: "nonce-1",
      targetOrigin: "https://preview.example.test",
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    };
    assert.equal(await replay.consume(nonce), true);
    assert.equal(
      await new PostgresScopeReplayStore(admin, ids.workspace).consume(nonce),
      false,
    );

    await admin.query(
      "INSERT INTO reaper_control.jobs(id,workspace_id,run_id,status,attempt,lease_expires_at,worker_id,payload) VALUES ($1,$2,$3,'RUNNING',1,now()+interval '10 minutes','dispatcher-test','{}'::jsonb)",
      ["20000000-0000-4000-8000-000000000007", ids.workspace, ids.run],
    );
    const prepared = await admin.query(
      "SELECT reaper_control.prepare_platform_execution_envelope($1,$2,$3::jsonb,now()+interval '5 minutes') AS prepared",
      [
        "20000000-0000-4000-8000-000000000007",
        "dispatcher-test",
        JSON.stringify({
          version: 1,
          runId: ids.run,
          workspaceId: ids.workspace,
          platform: {
            jobId: "20000000-0000-4000-8000-000000000007",
            workerId: "dispatcher-test",
          },
        }),
      ],
    );
    assert.equal(prepared.rows[0].prepared, true);
    const loaded = await admin.query(
      "SELECT * FROM reaper_control.load_platform_execution_envelope($1,$2)",
      ["20000000-0000-4000-8000-000000000007", "dispatcher-test"],
    );
    assert.equal(loaded.rows[0].run_id, ids.run);
    assert.equal(loaded.rows[0].envelope.workspaceId, ids.workspace);

    const audit = new PostgresAuditStore(admin, ids.workspace);
    await audit.append(ids.run, {
      type: "RUN_CREATED",
      data: { mode: "cloud-run" },
    });
    await audit.append(ids.run, { type: "RUN_STARTED" });
    assert.equal(
      await new PostgresAuditStore(admin, ids.workspace).verify(ids.run),
      true,
    );

    await admin.query(
      "UPDATE reaper_control.audit_heads SET event_hash=$1 WHERE workspace_id=$2 AND run_id=$3",
      ["f".repeat(64), ids.workspace, ids.run],
    );
    await assert.rejects(
      () => new PostgresAuditStore(admin, ids.workspace).verify(ids.run),
      /head mismatch/,
    );
  } finally {
    await admin.query("DROP SCHEMA IF EXISTS reaper_control CASCADE");
    await admin.end();
  }
});
