import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import pg from "pg";

const connectionString = process.env.REAPER_TEST_DATABASE_URL;
if (!connectionString)
  throw new Error(
    "Set REAPER_TEST_DATABASE_URL to a disposable PostgreSQL database.",
  );

const baseMigration = await readFile(
  fileURLToPath(new URL("../../control-plane/001_init.sql", import.meta.url)),
  "utf8",
);
const platformMigration = await readFile(
  fileURLToPath(
    new URL("../../control-plane/002_platform.sql", import.meta.url),
  ),
  "utf8",
);
const hardeningMigration = await readFile(
  fileURLToPath(
    new URL("../../control-plane/003_staging_hardening.sql", import.meta.url),
  ),
  "utf8",
);
const cloudRunMigration = await readFile(
  fileURLToPath(
    new URL("../../control-plane/004_cloud_run.sql", import.meta.url),
  ),
  "utf8",
);
const cloudRunIndexMigration = await readFile(
  fileURLToPath(
    new URL("../../control-plane/005_cloud_run_indexes.sql", import.meta.url),
  ),
  "utf8",
);
const freeRunnerMigration = await readFile(
  fileURLToPath(
    new URL("../../control-plane/006_free_runner.sql", import.meta.url),
  ),
  "utf8",
);

test("platform API key auth and durable job leasing respect workspace isolation", async () => {
  const admin = new pg.Client({ connectionString });
  await admin.connect();
  const apiRole = `reaper_api_test_${process.pid}`;
  const workerRole = `reaper_worker_test_${process.pid}`;
  const password = "synthetic-platform-password";
  const ids = {
    org: "10000000-0000-4000-8000-000000000001",
    workspace: "10000000-0000-4000-8000-000000000002",
    project: "10000000-0000-4000-8000-000000000003",
    assessment: "10000000-0000-4000-8000-000000000004",
    run: "10000000-0000-4000-8000-000000000005",
    job: "10000000-0000-4000-8000-000000000006",
    key: "10000000-0000-4000-8000-000000000007",
  };
  const principal = "platform-owner";
  const token = `reaper_live_${ids.key}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`;
  const pepper = "p".repeat(64);
  const secretHash = createHmac("sha256", pepper).update(token).digest("hex");
  let api;
  let worker;

  try {
    await admin.query("DROP SCHEMA IF EXISTS reaper_control CASCADE");
    await admin.query(baseMigration);
    await admin.query(platformMigration);
    await admin.query(hardeningMigration);
    await admin.query(cloudRunMigration);
    await admin.query(cloudRunIndexMigration);
    await admin.query(freeRunnerMigration);

    await admin.query(
      "SELECT reaper_control.bootstrap_platform($1,$2,$3,$4,$5,$6,$7,$8,NULL)",
      [
        ids.org,
        "Platform Org",
        ids.workspace,
        "Workspace",
        principal,
        ids.key,
        "test-admin",
        secretHash,
      ],
    );

    await admin.query(`CREATE ROLE ${apiRole} LOGIN PASSWORD '${password}'`);
    await admin.query(`CREATE ROLE ${workerRole} LOGIN PASSWORD '${password}'`);
    await admin.query(`GRANT reaper_platform_api TO ${apiRole}`);
    await admin.query(`GRANT reaper_platform_worker TO ${workerRole}`);

    const url = new URL(connectionString);
    url.username = apiRole;
    url.password = password;
    api = new pg.Client({ connectionString: url.toString() });
    await api.connect();

    const authenticated = await api.query(
      "SELECT * FROM reaper_control.authenticate_api_key($1::uuid,$2)",
      [ids.key, secretHash],
    );
    assert.equal(authenticated.rows[0].workspace_id, ids.workspace);
    assert.equal(authenticated.rows[0].principal_id, principal);
    assert.equal(authenticated.rows[0].role, "admin");

    await api.query("BEGIN");
    await api.query(
      "SELECT set_config('reaper.workspace_id',$1,true), set_config('reaper.principal_id',$2,true)",
      [ids.workspace, principal],
    );
    await api.query(
      "INSERT INTO reaper_control.projects(id,workspace_id,name) VALUES ($1,$2,'Project')",
      [ids.project, ids.workspace],
    );
    await api.query(
      "INSERT INTO reaper_control.assessments(id,workspace_id,project_id,reference) VALUES ($1,$2,$3,$4)",
      [ids.assessment, ids.workspace, ids.project, ids.assessment],
    );
    await api.query(
      `INSERT INTO reaper_control.runs(
         id,workspace_id,project_id,assessment_id,status,target_origin,environment,config_path
       ) VALUES ($1,$2,$3,$4,'PENDING','https://preview.example.test','staging','assessment.ts')`,
      [ids.run, ids.workspace, ids.project, ids.assessment],
    );
    await api.query(
      "INSERT INTO reaper_control.jobs(id,workspace_id,run_id,status,payload) VALUES ($1,$2,$3,'PENDING',$4::jsonb)",
      [
        ids.job,
        ids.workspace,
        ids.run,
        JSON.stringify({
          projectId: ids.project,
          assessmentId: ids.assessment,
          targetOrigin: "https://preview.example.test",
          environment: "staging",
          configPath: "assessment.ts",
        }),
      ],
    );
    await api.query("COMMIT");

    const workerUrl = new URL(connectionString);
    workerUrl.username = workerRole;
    workerUrl.password = password;
    worker = new pg.Client({ connectionString: workerUrl.toString() });
    await worker.connect();

    const leased = await worker.query(
      "SELECT * FROM reaper_control.lease_platform_job('worker-test',60)",
    );
    assert.equal(leased.rows[0].id, ids.job);
    assert.equal(leased.rows[0].workspace_id, ids.workspace);
    assert.equal(leased.rows[0].attempt, 1);

    const completed = await worker.query(
      "SELECT reaper_control.complete_platform_job($1,'worker-test',$2::jsonb) AS ok",
      [ids.job, JSON.stringify({ findings: [] })],
    );
    assert.equal(completed.rows[0].ok, true);

    const run = await admin.query(
      "SELECT status,report FROM reaper_control.runs WHERE id=$1",
      [ids.run],
    );
    assert.equal(run.rows[0].status, "COMPLETED");
    assert.deepEqual(run.rows[0].report, { findings: [] });
  } finally {
    if (api) await api.end().catch(() => {});
    if (worker) await worker.end().catch(() => {});
    await admin.query("DROP SCHEMA IF EXISTS reaper_control CASCADE");
    await admin.query(`DROP ROLE IF EXISTS ${apiRole}`);
    await admin.query(`DROP ROLE IF EXISTS ${workerRole}`);
    await admin.end();
  }
});
