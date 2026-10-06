import { test } from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { introspect, analyzeDatabase } from "../../dist/index.js";
const connectionString = process.env.REAPER_TEST_DATABASE_URL;
if (!connectionString)
  throw new Error(
    "Set REAPER_TEST_DATABASE_URL to a disposable PostgreSQL database.",
  );
test("live PostgreSQL catalogs, policies, grants and read-only role", async () => {
  const admin = new pg.Client({ connectionString });
  await admin.connect();
  const schema = "reaper_test_" + process.pid;
  const role = "reaper_reader_" + process.pid;
  const inheritedRole = "reaper_inherited_" + process.pid;
  try {
    await admin.query(`CREATE SCHEMA ${schema}`);
    await admin.query(
      `CREATE ROLE ${role} LOGIN PASSWORD 'synthetic-test-password'`,
    );
    await admin.query(`CREATE ROLE ${inheritedRole}`);
    await admin.query(`GRANT ${inheritedRole} TO ${role}`);
    await admin.query(
      `CREATE TABLE ${schema}.exposed(id integer PRIMARY KEY, owner_id text)`,
    );
    await admin.query(`GRANT SELECT, TRUNCATE ON ${schema}.exposed TO PUBLIC`);
    await admin.query(`GRANT SELECT ON ${schema}.exposed TO ${inheritedRole}`);
    await admin.query(
      `CREATE TABLE ${schema}.scoped(id integer PRIMARY KEY, owner_id text)`,
    );
    await admin.query(`ALTER TABLE ${schema}.scoped ENABLE ROW LEVEL SECURITY`);
    await admin.query(
      `CREATE POLICY owner_read ON ${schema}.scoped FOR SELECT TO PUBLIC USING (owner_id = current_user)`,
    );
    await admin.query(`CREATE TABLE ${schema}.open_policy(id integer)`);
    await admin.query(
      `ALTER TABLE ${schema}.open_policy ENABLE ROW LEVEL SECURITY`,
    );
    await admin.query(
      `CREATE POLICY all_read ON ${schema}.open_policy FOR SELECT TO PUBLIC USING (true)`,
    );
    await admin.query(`GRANT CREATE ON SCHEMA ${schema} TO PUBLIC`);
    await admin.query(
      `CREATE FUNCTION ${schema}.dangerous_rpc() RETURNS integer LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'`,
    );
    const readerUrl = new URL(connectionString);
    readerUrl.username = role;
    readerUrl.password = "synthetic-test-password";
    const before = await admin.query(
      `SELECT count(*)::int AS count FROM pg_catalog.pg_class WHERE relnamespace=$1::regnamespace`,
      [schema],
    );
    const snapshot = await introspect(readerUrl.toString());
    assert.ok(snapshot.serverVersion);
    assert.ok(snapshot.roles.some((r) => r.name === role && !r.superuser));
    const findings = analyzeDatabase(snapshot).filter(
      (f) => f.resource === schema || f.resource.startsWith(schema + "."),
    );
    assert.deepEqual(findings.map((f) => f.ruleId).sort(), [
      "REAPER-PG-001",
      "REAPER-PRIV-001",
      "REAPER-PRIV-002",
      "REAPER-RLS-001",
      "REAPER-RLS-003",
    ]);
    assert.ok(
      snapshot.memberships.some(
        (membership) =>
          membership.member === role && membership.role === inheritedRole,
      ),
    );
    assert.ok(
      snapshot.functions.some(
        (fn) => fn.schema === schema && fn.name === "dangerous_rpc",
      ),
    );
    assert.ok(!findings.some((f) => f.resource === schema + ".scoped"));
    const after = await admin.query(
      `SELECT count(*)::int AS count FROM pg_catalog.pg_class WHERE relnamespace=$1::regnamespace`,
      [schema],
    );
    assert.deepEqual(after.rows, before.rows);
  } finally {
    await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await admin.query(`REVOKE ${inheritedRole} FROM ${role}`);
    await admin.query(`DROP ROLE IF EXISTS ${role}`);
    await admin.query(`DROP ROLE IF EXISTS ${inheritedRole}`);
    await admin.end();
  }
});
