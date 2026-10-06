import pg from "pg";
import { finding } from "./findings.js";
import type { Finding } from "./model.js";
export interface Table {
  schema: string;
  name: string;
  rls: boolean;
  force: boolean;
  owner: string;
}
export interface Policy {
  schema: string;
  table: string;
  name: string;
  roles: string[];
  command: string;
  permissive: string;
  using: string | null;
  check: string | null;
}
export interface Role {
  name: string;
  superuser: boolean;
  bypassRls: boolean;
  login: boolean;
}
export interface Grant {
  schema: string;
  table: string;
  role: string;
  privilege: string;
}
export interface DatabaseSnapshot {
  tables: Table[];
  policies: Policy[];
  roles: Role[];
  grants: Grant[];
  serverVersion: string;
  limitations: string[];
}
export async function introspect(
  connectionString: string,
): Promise<DatabaseSnapshot> {
  const client = new pg.Client({
    connectionString,
    connectionTimeoutMillis: 5000,
    query_timeout: 10000,
    application_name: "reaper-readonly",
  });
  try {
    await client.connect();
    await client.query(
      "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY",
    );
    await client.query("SET LOCAL statement_timeout = '5s'");
    await client.query("SET LOCAL lock_timeout = '1s'");
    const tables = await client.query<Table>(
      `SELECT n.nspname AS schema, c.relname AS name, c.relrowsecurity AS rls, c.relforcerowsecurity AS force, pg_catalog.pg_get_userbyid(c.relowner) AS owner FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind IN ('r','p') AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' ORDER BY 1,2`,
    );
    const policies = await client.query<Policy>(
      "SELECT schemaname AS schema, tablename AS table, policyname AS name, roles::text[] AS roles, cmd AS command, permissive, qual AS using, with_check AS check FROM pg_catalog.pg_policies ORDER BY 1,2,3",
    );
    const roles = await client.query<Role>(
      'SELECT rolname AS name, rolsuper AS superuser, rolbypassrls AS "bypassRls", rolcanlogin AS login FROM pg_catalog.pg_roles ORDER BY 1',
    );
    const grants = await client.query<Grant>(
      `SELECT n.nspname AS schema, c.relname AS table, CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee) END AS role, a.privilege_type AS privilege FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(c.relacl,pg_catalog.acldefault('r',c.relowner))) a WHERE c.relkind IN ('r','p') AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' ORDER BY 1,2,3,4`,
    );
    const version = await client.query<{ server_version: string }>(
      "SHOW server_version",
    );
    await client.query("ROLLBACK");
    return {
      tables: tables.rows,
      policies: policies.rows,
      roles: roles.rows,
      grants: grants.rows,
      serverVersion: version.rows[0]!.server_version,
      limitations: [
        "Catalog visibility depends on the connected role.",
        "Role inheritance, views, functions, column ACLs and runtime JWT claims are not evaluated.",
        "Open-policy findings are candidates: restrictive policy composition is not proven.",
      ],
    };
  } catch (error) {
    // Do not echo connection strings or driver messages containing credentials.
    const code =
      error && typeof error === "object" && "code" in error
        ? String(error.code)
        : "UNKNOWN";
    throw new Error(
      `PostgreSQL introspection failed (${/^[A-Z0-9_]+$/.test(code) ? code : "UNKNOWN"}). Check connectivity, TLS and catalog permissions.`,
    );
  } finally {
    await client.end();
  }
}
export function analyzeDatabase(snapshot: DatabaseSnapshot): Finding[] {
  const findings: Finding[] = [];
  const broad = new Set(["PUBLIC", "public", "anon", "authenticated"]);
  for (const table of snapshot.tables) {
    const resource = `${table.schema}.${table.name}`;
    const grants = snapshot.grants.filter(
      (g) =>
        g.schema === table.schema &&
        g.table === table.name &&
        broad.has(g.role),
    );
    const policies = snapshot.policies.filter(
      (p) => p.schema === table.schema && p.table === table.name,
    );
    const add = (
      ruleId: string,
      title: string,
      severity: Finding["severity"],
      category: Finding["category"],
      evidence: string[],
      identity: string,
    ) =>
      findings.push(
        finding(
          {
            file: `database/${table.schema}/${table.name}`,
            line: 1,
            column: 1,
            ruleId,
            title,
            severity,
            confidence: "MEDIUM",
            category,
            resource,
            description: evidence.join(" "),
            evidence,
            dataFlow: [],
            recommendation:
              "Review intended role access, policy composition and application exposure. Apply least privilege through a reviewed migration.",
          },
          identity,
        ),
      );
    if (
      !table.rls &&
      grants.some((g) =>
        ["SELECT", "INSERT", "UPDATE", "DELETE"].includes(g.privilege),
      )
    )
      add(
        "REAPER-RLS-001",
        "Broad role grant without RLS",
        "HIGH",
        "RLS",
        grants.map((g) => `${g.role}: ${g.privilege}; RLS disabled`),
        "no-rls",
      );
    if (table.rls && policies.length === 0)
      add(
        "REAPER-RLS-002",
        "RLS enabled without policies",
        "INFO",
        "RLS",
        [
          "Ordinary roles are denied by default; owners and bypass roles may still access the table.",
        ],
        "no-policies",
      );
    for (const policy of policies) {
      const unconditional = (s: string | null) =>
        s !== null && /^\(*\s*true\s*\)*$/i.test(s.trim());
      if (
        policy.permissive === "PERMISSIVE" &&
        policy.roles.some((r) => broad.has(r)) &&
        (unconditional(policy.using) || unconditional(policy.check))
      )
        add(
          "REAPER-RLS-003",
          "Unconditional permissive policy",
          "MEDIUM",
          "RLS",
          [
            `Policy ${policy.name}; operation ${policy.command}; roles ${policy.roles.join(", ")}`,
            "Constant TRUE permits all rows in this policy. Restrictive policies and grants may reduce effective access.",
          ],
          policy.name,
        );
    }
    for (const grant of grants.filter((g) =>
      ["TRUNCATE", "TRIGGER", "REFERENCES"].includes(g.privilege),
    ))
      add(
        "REAPER-PRIV-001",
        "Broad role has elevated table privilege",
        "HIGH",
        "Privileges",
        [
          `${grant.role} has ${grant.privilege}`,
          "RLS does not protect TRUNCATE or REFERENCES operations.",
        ],
        `${grant.role}:${grant.privilege}`,
      );
  }
  return findings;
}
