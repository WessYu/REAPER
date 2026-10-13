import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import pg from "pg";

const connectionString = process.env.REAPER_TEST_DATABASE_URL;
if (!connectionString)
  throw new Error(
    "Set REAPER_TEST_DATABASE_URL to a disposable PostgreSQL database.",
  );

const migration = await readFile(
  fileURLToPath(new URL("../../control-plane/001_init.sql", import.meta.url)),
  "utf8",
);

const ids = {
  orgA: "00000000-0000-4000-8000-000000000001",
  orgB: "00000000-0000-4000-8000-000000000002",
  workspaceA: "00000000-0000-4000-8000-000000000011",
  workspaceB: "00000000-0000-4000-8000-000000000012",
  projectA: "00000000-0000-4000-8000-000000000021",
  projectB: "00000000-0000-4000-8000-000000000022",
  assessmentA: "00000000-0000-4000-8000-000000000031",
  assessmentB: "00000000-0000-4000-8000-000000000032",
  runA: "00000000-0000-4000-8000-000000000041",
  runB: "00000000-0000-4000-8000-000000000042",
  findingA: "00000000-0000-4000-8000-000000000051",
  findingB: "00000000-0000-4000-8000-000000000052",
};

async function setWorkspace(client, workspaceId, principalId) {
  await client.query("BEGIN");
  await client.query(
    "SELECT set_config('reaper.workspace_id', $1, true), set_config('reaper.principal_id', $2, true)",
    [workspaceId, principalId],
  );
}

test("control-plane RLS blocks cross-workspace reads and writes even without WHERE clauses", async () => {
  const admin = new pg.Client({ connectionString });
  await admin.connect();
  const role = `reaper_cp_${process.pid}`;
  const password = "synthetic-control-plane-password";
  let app;
  try {
    await admin.query("DROP SCHEMA IF EXISTS reaper_control CASCADE");
    await admin.query(migration);
    await admin.query(`CREATE ROLE ${role} LOGIN PASSWORD '${password}'`);
    await admin.query("GRANT USAGE ON SCHEMA reaper_control TO " + role);
    await admin.query(
      "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA reaper_control TO " +
        role,
    );
    await admin.query(
      "GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA reaper_control TO " + role,
    );

    await admin.query(
      "INSERT INTO reaper_control.organizations(id,name) VALUES ($1,'Org A'),($2,'Org B')",
      [ids.orgA, ids.orgB],
    );
    await admin.query(
      "INSERT INTO reaper_control.workspaces(id,organization_id,name) VALUES ($1,$2,'Workspace A'),($3,$4,'Workspace B')",
      [ids.workspaceA, ids.orgA, ids.workspaceB, ids.orgB],
    );
    await admin.query(
      "INSERT INTO reaper_control.workspace_members(workspace_id,principal_id,role) VALUES ($1,'alice','analyst'),($2,'bob','viewer')",
      [ids.workspaceA, ids.workspaceB],
    );
    await admin.query(
      "INSERT INTO reaper_control.projects(id,workspace_id,name) VALUES ($1,$2,'Project A'),($3,$4,'Project B')",
      [ids.projectA, ids.workspaceA, ids.projectB, ids.workspaceB],
    );
    await admin.query(
      "INSERT INTO reaper_control.assessments(id,workspace_id,project_id,reference) VALUES ($1,$2,$3,'assessment-a'),($4,$5,$6,'assessment-b')",
      [
        ids.assessmentA,
        ids.workspaceA,
        ids.projectA,
        ids.assessmentB,
        ids.workspaceB,
        ids.projectB,
      ],
    );
    await admin.query(
      "INSERT INTO reaper_control.runs(id,workspace_id,project_id,assessment_id,status,target_origin) VALUES ($1,$2,$3,$4,'COMPLETED','https://a.example.test'),($5,$6,$7,$8,'COMPLETED','https://b.example.test')",
      [
        ids.runA,
        ids.workspaceA,
        ids.projectA,
        ids.assessmentA,
        ids.runB,
        ids.workspaceB,
        ids.projectB,
        ids.assessmentB,
      ],
    );
    await admin.query(
      "INSERT INTO reaper_control.findings(id,workspace_id,run_id,rule_id,severity) VALUES ($1,$2,$3,'A-001','HIGH'),($4,$5,$6,'B-001','HIGH')",
      [
        ids.findingA,
        ids.workspaceA,
        ids.runA,
        ids.findingB,
        ids.workspaceB,
        ids.runB,
      ],
    );

    const url = new URL(connectionString);
    url.username = role;
    url.password = password;
    app = new pg.Client({ connectionString: url.toString() });
    await app.connect();

    await setWorkspace(app, ids.workspaceA, "alice");
    const aRows = await app.query(
      "SELECT workspace_id, rule_id FROM reaper_control.findings ORDER BY rule_id",
    );
    assert.deepEqual(aRows.rows, [
      { workspace_id: ids.workspaceA, rule_id: "A-001" },
    ]);

    const crossUpdate = await app.query(
      "UPDATE reaper_control.findings SET severity='LOW' WHERE id=$1",
      [ids.findingB],
    );
    assert.equal(crossUpdate.rowCount, 0);
    const crossDelete = await app.query(
      "DELETE FROM reaper_control.findings WHERE id=$1",
      [ids.findingB],
    );
    assert.equal(crossDelete.rowCount, 0);
    await assert.rejects(
      app.query(
        "INSERT INTO reaper_control.findings(id,workspace_id,run_id,rule_id,severity) VALUES ('00000000-0000-4000-8000-000000000099',$1,$2,'X-001','HIGH')",
        [ids.workspaceB, ids.runB],
      ),
      /row-level security policy/,
    );
    await app.query("ROLLBACK");

    await setWorkspace(app, ids.workspaceB, "bob");
    const bRows = await app.query(
      "SELECT workspace_id, rule_id FROM reaper_control.findings ORDER BY rule_id",
    );
    assert.deepEqual(bRows.rows, [
      { workspace_id: ids.workspaceB, rule_id: "B-001" },
    ]);
    await app.query("ROLLBACK");

    await app.query("BEGIN");
    const noContext = await app.query(
      "SELECT workspace_id, rule_id FROM reaper_control.findings",
    );
    assert.deepEqual(noContext.rows, []);
    await assert.rejects(
      app.query(
        "INSERT INTO reaper_control.findings(id,workspace_id,run_id,rule_id,severity) VALUES ('00000000-0000-4000-8000-000000000098',$1,$2,'NOCTX','HIGH')",
        [ids.workspaceA, ids.runA],
      ),
      /row-level security policy/,
    );
    await app.query("ROLLBACK");

    const verifyB = await admin.query(
      "SELECT severity FROM reaper_control.findings WHERE id=$1",
      [ids.findingB],
    );
    assert.equal(verifyB.rows[0].severity, "HIGH");
  } finally {
    if (app) await app.end().catch(() => {});
    await admin.query("DROP SCHEMA IF EXISTS reaper_control CASCADE");
    await admin.query(`DROP ROLE IF EXISTS ${role}`);
    await admin.end();
  }
});
