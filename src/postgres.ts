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
  inherit: boolean;
}
export interface RoleMembership {
  member: string;
  role: string;
  adminOption: boolean;
}
export interface Grant {
  schema: string;
  table: string;
  role: string;
  privilege: string;
}
export interface SchemaGrant {
  schema: string;
  role: string;
  privilege: string;
}
export interface ColumnGrant {
  schema: string;
  table: string;
  column: string;
  role: string;
  privilege: string;
}
export interface DatabaseFunction {
  schema: string;
  name: string;
  identityArguments: string;
  owner: string;
  securityDefiner: boolean;
  config: string[] | null;
  executeRoles: string[];
}
export interface DatabaseSnapshot {
  tables: Table[];
  policies: Policy[];
  roles: Role[];
  memberships: RoleMembership[];
  grants: Grant[];
  schemaGrants: SchemaGrant[];
  columnGrants: ColumnGrant[];
  functions: DatabaseFunction[];
  serverVersion: string;
  limitations: string[];
}

const catalogFilter =
  "n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%'";

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
      `SELECT n.nspname AS schema,
              c.relname AS name,
              c.relrowsecurity AS rls,
              c.relforcerowsecurity AS force,
              pg_catalog.pg_get_userbyid(c.relowner) AS owner
         FROM pg_catalog.pg_class c
         JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        WHERE c.relkind IN ('r','p') AND ${catalogFilter}
        ORDER BY 1,2`,
    );

    const policies = await client.query<Policy>(
      "SELECT schemaname AS schema, tablename AS table, policyname AS name, roles::text[] AS roles, cmd AS command, permissive, qual AS using, with_check AS check FROM pg_catalog.pg_policies ORDER BY 1,2,3",
    );

    const roles = await client.query<Role>(
      'SELECT rolname AS name, rolsuper AS superuser, rolbypassrls AS "bypassRls", rolcanlogin AS login, rolinherit AS inherit FROM pg_catalog.pg_roles ORDER BY 1',
    );

    const memberships = await client.query<RoleMembership>(
      'SELECT member.rolname AS member, parent.rolname AS role, m.admin_option AS "adminOption" FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles parent ON parent.oid=m.roleid JOIN pg_catalog.pg_roles member ON member.oid=m.member ORDER BY 1,2',
    );

    const grants = await client.query<Grant>(
      `SELECT n.nspname AS schema,
              c.relname AS table,
              CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee) END AS role,
              a.privilege_type AS privilege
         FROM pg_catalog.pg_class c
         JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
         CROSS JOIN LATERAL pg_catalog.aclexplode(
           COALESCE(c.relacl,pg_catalog.acldefault('r',c.relowner))
         ) a
        WHERE c.relkind IN ('r','p') AND ${catalogFilter}
        ORDER BY 1,2,3,4`,
    );

    const schemaGrants = await client.query<SchemaGrant>(
      `SELECT n.nspname AS schema,
              CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee) END AS role,
              a.privilege_type AS privilege
         FROM pg_catalog.pg_namespace n
         CROSS JOIN LATERAL pg_catalog.aclexplode(
           COALESCE(n.nspacl,pg_catalog.acldefault('n',n.nspowner))
         ) a
        WHERE ${catalogFilter}
        ORDER BY 1,2,3`,
    );

    const columnGrants = await client.query<ColumnGrant>(
      `SELECT table_schema AS schema,
              table_name AS table,
              column_name AS column,
              grantee AS role,
              privilege_type AS privilege
         FROM information_schema.column_privileges
        WHERE table_schema NOT IN ('pg_catalog','information_schema')
        ORDER BY 1,2,3,4,5`,
    );

    const functions = await client.query<DatabaseFunction>(
      `SELECT n.nspname AS schema,
              p.proname AS name,
              pg_catalog.pg_get_function_identity_arguments(p.oid) AS "identityArguments",
              pg_catalog.pg_get_userbyid(p.proowner) AS owner,
              p.prosecdef AS "securityDefiner",
              p.proconfig AS config,
              ARRAY(
                SELECT CASE
                         WHEN x.grantee=0 THEN 'PUBLIC'
                         ELSE pg_catalog.pg_get_userbyid(x.grantee)
                       END
                  FROM pg_catalog.aclexplode(
                    COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))
                  ) x
                 WHERE x.privilege_type='EXECUTE'
                 ORDER BY 1
              )::text[] AS "executeRoles"
         FROM pg_catalog.pg_proc p
         JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
        WHERE ${catalogFilter}
        ORDER BY 1,2,3`,
    );

    const version = await client.query<{ server_version: string }>(
      "SHOW server_version",
    );
    await client.query("ROLLBACK");

    return {
      tables: tables.rows,
      policies: policies.rows,
      roles: roles.rows,
      memberships: memberships.rows,
      grants: grants.rows,
      schemaGrants: schemaGrants.rows,
      columnGrants: columnGrants.rows,
      functions: functions.rows,
      serverVersion: version.rows[0]!.server_version,
      limitations: [
        "Catalog visibility depends on the connected role.",
        "Role inheritance is modeled only through PostgreSQL role memberships and ROLINHERIT; SET ROLE and runtime JWT/session claims are not proven.",
        "Views, materialized-view definitions, triggers and extension-specific privilege models are not evaluated yet.",
        "Open-policy findings are candidates: arbitrary policy expressions are not symbolically evaluated.",
      ],
    };
  } catch (error) {
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

function effectiveRoles(snapshot: DatabaseSnapshot, role: string): Set<string> {
  const result = new Set<string>([role]);
  const queue = [role];
  while (queue.length) {
    const member = queue.shift()!;
    const metadata = snapshot.roles.find(
      (candidate) => candidate.name === member,
    );
    if (metadata && !metadata.inherit) continue;
    for (const edge of snapshot.memberships)
      if (edge.member === member && !result.has(edge.role)) {
        result.add(edge.role);
        queue.push(edge.role);
      }
  }
  return result;
}

export function broadGrant(
  snapshot: DatabaseSnapshot,
  role: string,
  broad = new Set(["PUBLIC", "public", "anon", "authenticated"]),
): boolean {
  if (broad.has(role)) return true;
  for (const principal of broad)
    if (effectiveRoles(snapshot, principal).has(role)) return true;
  return false;
}

export function effectiveTableGrants(
  snapshot: DatabaseSnapshot,
  schema: string,
  table: string,
  principals = ["PUBLIC", "anon", "authenticated"],
): Grant[] {
  const effective = new Set<string>(["PUBLIC"]);
  for (const principal of principals)
    for (const role of effectiveRoles(snapshot, principal)) effective.add(role);
  return snapshot.grants.filter(
    (grant) =>
      grant.schema === schema &&
      grant.table === table &&
      effective.has(grant.role),
  );
}

function configuredSearchPath(fn: DatabaseFunction): string | undefined {
  return fn.config
    ?.find((entry) => entry.startsWith("search_path="))
    ?.slice("search_path=".length);
}

export function unsafeSecurityDefinerSearchPath(fn: DatabaseFunction): boolean {
  const configured = configuredSearchPath(fn);
  if (!configured) return true;
  const schemas = configured
    .split(",")
    .map((entry) => entry.trim().replace(/^"|"$/g, ""))
    .filter(Boolean);
  return schemas.some(
    (schema) =>
      schema === "$user" || schema === "public" || schema === "pg_temp",
  );
}

export function analyzeDatabase(snapshot: DatabaseSnapshot): Finding[] {
  const findings: Finding[] = [];
  const broad = new Set(["PUBLIC", "public", "anon", "authenticated"]);
  const add = (
    resource: string,
    ruleId: string,
    title: string,
    severity: Finding["severity"],
    category: Finding["category"],
    evidence: string[],
    identity: string,
    recommendation: string,
  ) =>
    findings.push(
      finding(
        {
          file: `database/${resource.replaceAll(".", "/")}`,
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
          recommendation,
        },
        identity,
      ),
    );

  for (const table of snapshot.tables) {
    const resource = `${table.schema}.${table.name}`;
    const grants = snapshot.grants.filter(
      (grant) =>
        grant.schema === table.schema &&
        grant.table === table.name &&
        broadGrant(snapshot, grant.role, broad),
    );
    const policies = snapshot.policies.filter(
      (policy) => policy.schema === table.schema && policy.table === table.name,
    );

    if (
      !table.rls &&
      grants.some((grant) =>
        ["SELECT", "INSERT", "UPDATE", "DELETE"].includes(grant.privilege),
      )
    )
      add(
        resource,
        "REAPER-RLS-001",
        "Broad role grant without RLS",
        "HIGH",
        "RLS",
        grants.map(
          (grant) =>
            `${grant.role}: ${grant.privilege}; effective broad access; RLS disabled`,
        ),
        "no-rls",
        "Review intended role access and enable reviewed RLS policies when direct client roles can reach the table.",
      );

    if (table.rls && policies.length === 0)
      add(
        resource,
        "REAPER-RLS-002",
        "RLS enabled without policies",
        "INFO",
        "RLS",
        [
          "Ordinary roles are denied by default; owners and bypass roles may still access the table.",
        ],
        "no-policies",
        "Confirm default-deny is intentional and review owner/bypass access.",
      );

    for (const policy of policies) {
      const unconditional = (expression: string | null) =>
        expression !== null && /^\(*\s*true\s*\)*$/i.test(expression.trim());
      if (
        policy.permissive === "PERMISSIVE" &&
        policy.roles.some((role) => broadGrant(snapshot, role, broad)) &&
        (unconditional(policy.using) || unconditional(policy.check))
      )
        add(
          resource,
          "REAPER-RLS-003",
          "Unconditional permissive policy",
          "MEDIUM",
          "RLS",
          [
            `Policy ${policy.name}; operation ${policy.command}; roles ${policy.roles.join(", ")}`,
            "Constant TRUE permits all rows for this permissive policy. Restrictive policies and grants may reduce effective access.",
          ],
          `policy:${policy.name}`,
          "Replace unconditional predicates with reviewed ownership/tenant predicates unless open access is intentional.",
        );
    }

    for (const grant of grants.filter((candidate) =>
      ["TRUNCATE", "TRIGGER", "REFERENCES"].includes(candidate.privilege),
    ))
      add(
        resource,
        "REAPER-PRIV-001",
        "Broad role has elevated table privilege",
        "HIGH",
        "Privileges",
        [
          `${grant.role} effectively grants ${grant.privilege} to a broad role`,
          "RLS does not protect TRUNCATE or REFERENCES operations.",
        ],
        `table-grant:${grant.role}:${grant.privilege}`,
        "Revoke elevated privileges from broad or inherited client roles and grant only the operations the application needs.",
      );
  }

  for (const grant of snapshot.schemaGrants)
    if (grant.privilege === "CREATE" && broadGrant(snapshot, grant.role, broad))
      add(
        grant.schema,
        "REAPER-PRIV-002",
        "Broad role can create objects in schema",
        "HIGH",
        "Privileges",
        [
          `${grant.role} effectively grants CREATE on schema ${grant.schema} to a broad role.`,
          "Writable schemas in a function search_path can contribute to object-hijacking risks.",
        ],
        `schema-create:${grant.schema}:${grant.role}`,
        "Revoke CREATE from broad roles on application/search-path schemas unless object creation is explicitly required.",
      );

  for (const role of snapshot.roles)
    if (broad.has(role.name) && (role.superuser || role.bypassRls))
      add(
        `role.${role.name}`,
        "REAPER-PRIV-003",
        "Broad application role bypasses database authorization controls",
        "CRITICAL",
        "Privileges",
        [
          `${role.name}: superuser=${role.superuser}; bypassRls=${role.bypassRls}`,
        ],
        `role-bypass:${role.name}`,
        "Use an unprivileged application role. Never expose superuser or BYPASSRLS roles to client-controlled sessions.",
      );

  for (const fn of snapshot.functions) {
    if (!fn.securityDefiner) continue;
    const broadExecute = fn.executeRoles.filter((role) =>
      broadGrant(snapshot, role, broad),
    );
    if (!broadExecute.length || !unsafeSecurityDefinerSearchPath(fn)) continue;

    const resource = `${fn.schema}.${fn.name}(${fn.identityArguments})`;
    const searchPath = configuredSearchPath(fn);
    add(
      resource,
      "REAPER-PG-001",
      "Broadly executable SECURITY DEFINER function has unsafe search_path",
      "HIGH",
      "Privileges",
      [
        `SECURITY DEFINER owner: ${fn.owner}`,
        `Effective broad EXECUTE through: ${broadExecute.join(", ")}`,
        searchPath
          ? `Configured search_path: ${searchPath}`
          : "No function-local search_path is configured.",
      ],
      `security-definer:${resource}`,
      "Restrict EXECUTE and set a function-local search_path containing only trusted schemas, typically pg_catalog plus explicitly trusted application schemas.",
    );
  }

  return findings;
}
