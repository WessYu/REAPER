import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import pg from "pg";

const connectionString = process.env.REAPER_TEST_DATABASE_URL;
if (!connectionString)
  throw new Error(
    "Set REAPER_TEST_DATABASE_URL to a disposable PostgreSQL database.",
  );

const migrations = await Promise.all(
  [
    "001_init.sql",
    "002_platform.sql",
    "003_staging_hardening.sql",
    "004_cloud_run.sql",
    "005_cloud_run_indexes.sql",
    "006_free_runner.sql",
  ].map((name) =>
    readFile(
      fileURLToPath(new URL("../../control-plane/" + name, import.meta.url)),
      "utf8",
    ),
  ),
);

test("free runner leases only the fixed read-only staging profile", async () => {
  const db = new pg.Client({ connectionString });
  await db.connect();

  const ids = {
    org: "60000000-0000-4000-8000-000000000001",
    workspace: "60000000-0000-4000-8000-000000000002",
    project: "60000000-0000-4000-8000-000000000003",
    safeAssessment: "60000000-0000-4000-8000-000000000004",
    unsafeAssessment: "60000000-0000-4000-8000-000000000005",
    safeRun: "60000000-0000-4000-8000-000000000006",
    unsafeRun: "60000000-0000-4000-8000-000000000007",
    safeJob: "60000000-0000-4000-8000-000000000008",
    unsafeJob: "60000000-0000-4000-8000-000000000009",
    key: "60000000-0000-4000-8000-000000000010",
  };

  try {
    await db.query("DROP SCHEMA IF EXISTS reaper_control CASCADE");
    for (const migration of migrations) await db.query(migration);
    await db.query(
      "SELECT reaper_control.bootstrap_platform($1,$2,$3,$4,$5,$6,$7,$8,NULL)",
      [
        ids.org,
        "Free Runner Org",
        ids.workspace,
        "Free Runner",
        "owner",
        ids.key,
        "bootstrap",
        "b".repeat(64),
      ],
    );

    await db.query("BEGIN");
    await db.query(
      "SELECT set_config('reaper.workspace_id',$1,true),set_config('reaper.principal_id','owner',true)",
      [ids.workspace],
    );
    await db.query(
      "INSERT INTO reaper_control.projects(id,workspace_id,name) VALUES ($1,$2,'Project')",
      [ids.project, ids.workspace],
    );
    await db.query(
      "INSERT INTO reaper_control.assessments(id,workspace_id,project_id,reference) VALUES ($1,$2,$3,'unsafe'),($4,$2,$3,'safe')",
      [
        ids.unsafeAssessment,
        ids.workspace,
        ids.project,
        ids.safeAssessment,
      ],
    );

    await db.query(
      `INSERT INTO reaper_control.runs(
         id,workspace_id,project_id,assessment_id,status,target_origin,
         environment,config_path,permissions,limits
       ) VALUES
       ($1,$2,$3,$4,'PENDING','https://unsafe.example.test','staging',
        'free-readonly.ts','["read","mutations"]'::jsonb,
        '{"maxRequests":8,"maxCleanupRequests":1,"rateLimitPerSecond":2,"deadlineMs":60000}'::jsonb),
       ($5,$2,$3,$6,'PENDING','https://safe.example.test','staging',
        'free-readonly.ts','["read"]'::jsonb,
        '{"maxRequests":8,"maxCleanupRequests":1,"rateLimitPerSecond":2,"deadlineMs":60000}'::jsonb)`,
      [
        ids.unsafeRun,
        ids.workspace,
        ids.project,
        ids.unsafeAssessment,
        ids.safeRun,
        ids.safeAssessment,
      ],
    );

    await db.query(
      "INSERT INTO reaper_control.jobs(id,workspace_id,run_id,status,payload) VALUES " +
        "($1,$2,$3,'PENDING',$4::jsonb),($5,$2,$6,'PENDING',$7::jsonb)",
      [
        ids.unsafeJob,
        ids.workspace,
        ids.unsafeRun,
        JSON.stringify({
          projectId: ids.project,
          assessmentId: ids.unsafeAssessment,
          targetOrigin: "https://unsafe.example.test",
          environment: "staging",
          configPath: "free-readonly.ts",
          permissions: ["read", "mutations"],
          limits: {
            maxRequests: 8,
            maxCleanupRequests: 1,
            rateLimitPerSecond: 2,
            deadlineMs: 60000,
          },
        }),
        ids.safeJob,
        ids.safeRun,
        JSON.stringify({
          projectId: ids.project,
          assessmentId: ids.safeAssessment,
          targetOrigin: "https://safe.example.test",
          environment: "staging",
          configPath: "free-readonly.ts",
          permissions: ["read"],
          limits: {
            maxRequests: 8,
            maxCleanupRequests: 1,
            rateLimitPerSecond: 2,
            deadlineMs: 60000,
          },
        }),
      ],
    );
    await db.query("COMMIT");

    const leased = await db.query(
      "SELECT * FROM reaper_control.lease_free_platform_job('gha:1:1',300)",
    );
    assert.equal(leased.rows.length, 1);
    assert.equal(leased.rows[0].id, ids.safeJob);
    assert.equal(leased.rows[0].run_id, ids.safeRun);

    const jobs = await db.query(
      "SELECT id,status,worker_id FROM reaper_control.jobs ORDER BY id",
    );
    const unsafe = jobs.rows.find((row) => row.id === ids.unsafeJob);
    const safe = jobs.rows.find((row) => row.id === ids.safeJob);
    assert.equal(unsafe.status, "PENDING");
    assert.equal(unsafe.worker_id, null);
    assert.equal(safe.status, "RUNNING");
    assert.equal(safe.worker_id, "gha:1:1");
  } finally {
    await db.query("DROP SCHEMA IF EXISTS reaper_control CASCADE");
    await db.end();
  }
});
