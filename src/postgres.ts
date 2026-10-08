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
  language?: string;
  definition?: string;
}
export interface DatabaseView {
  schema: string;
  name: string;
  owner: string;
  materialized: boolean;
  securityInvoker: boolean;
  definition: string;
  dependencies?: string[];
}
export interface DatabaseTrigger {
  schema: string;
  table: string;
  name: string;
  functionSchema: string;
  functionName: string;
  enabled: string;
  definition?: string;
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
  views: DatabaseView[];
  triggers: DatabaseTrigger[];
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
        WHERE c.relkind IN ('r','p','v','m') AND ${catalogFilter}
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
              l.lanname AS language,
              pg_catalog.pg_get_functiondef(p.oid) AS definition,
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
         JOIN pg_catalog.pg_language l ON l.oid=p.prolang
        WHERE ${catalogFilter}
        ORDER BY 1,2,3`,
    );

    const views = await client.query<DatabaseView>(
      `SELECT n.nspname AS schema,
              c.relname AS name,
              pg_catalog.pg_get_userbyid(c.relowner) AS owner,
              (c.relkind='m') AS materialized,
              COALESCE('security_invoker=true'=ANY(c.reloptions),false) AS "securityInvoker",
              pg_catalog.pg_get_viewdef(c.oid,true) AS definition,
              ARRAY(
                SELECT DISTINCT dn.nspname || '.' || dc.relname
                  FROM pg_catalog.pg_rewrite rw
                  JOIN pg_catalog.pg_depend d
                    ON d.classid='pg_rewrite'::regclass
                   AND d.objid=rw.oid
                   AND d.deptype='n'
                  JOIN pg_catalog.pg_class dc ON dc.oid=d.refobjid
                  JOIN pg_catalog.pg_namespace dn ON dn.oid=dc.relnamespace
                 WHERE rw.ev_class=c.oid
                   AND dc.oid<>c.oid
                   AND dc.relkind IN ('r','p','v','m')
                 ORDER BY 1
              )::text[] AS dependencies
         FROM pg_catalog.pg_class c
         JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        WHERE c.relkind IN ('v','m') AND ${catalogFilter}
        ORDER BY 1,2`,
    );

    const triggers = await client.query<DatabaseTrigger>(
      `SELECT n.nspname AS schema,
              c.relname AS table,
              t.tgname AS name,
              pn.nspname AS "functionSchema",
              p.proname AS "functionName",
              t.tgenabled::text AS enabled,
              pg_catalog.pg_get_triggerdef(t.oid,true) AS definition
         FROM pg_catalog.pg_trigger t
         JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid
         JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
         JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid
         JOIN pg_catalog.pg_namespace pn ON pn.oid=p.pronamespace
        WHERE NOT t.tgisinternal AND ${catalogFilter}
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
      views: views.rows,
      triggers: triggers.rows,
      serverVersion: version.rows[0]!.server_version,
      limitations: [
        "Catalog visibility depends on the connected role.",
        "Role inheritance is modeled only through PostgreSQL role memberships and ROLINHERIT; SET ROLE and runtime JWT/session claims are not proven.",
        "View and trigger posture is inspected, but dependency-level privilege composition remains conservative.",
        "RLS expressions are symbolically classified for common auth.uid(), JWT tenant and role-only patterns; arbitrary SQL predicates are not theorem-proved.",
        "Extension-specific privilege models outside recognized Supabase/PostgreSQL catalogs may require manual review.",
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

export type PolicyExpressionClass =
  | "identity"
  | "tenant"
  | "role-only"
  | "constant-open"
  | "constant-deny"
  | "unknown";

export function classifyPolicyExpression(
  expression: string | null,
): PolicyExpressionClass {
  if (!expression) return "unknown";
  const normalized = expression
    .replace(/::[a-zA-Z0-9_."\[\]]+/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
  if (/^\(*\s*true\s*\)*$/.test(normalized)) return "constant-open";
  if (/^\(*\s*false\s*\)*$/.test(normalized)) return "constant-deny";
  if (/auth\.uid\s*\(\s*\)/.test(normalized)) return "identity";
  if (
    /(auth\.jwt\s*\(\s*\)|current_setting\s*\([^)]*(?:jwt|claim|tenant|organization|workspace|account))/.test(
      normalized,
    ) &&
    /(?:tenant|organization|workspace|account|org)[_-]?id/.test(normalized)
  )
    return "tenant";
  if (
    /(auth\.role\s*\(\s*\)|current_user|session_user)/.test(normalized) &&
    !/(?:user|owner|tenant|organization|workspace|account|org)[_-]?id/.test(
      normalized,
    )
  )
    return "role-only";
  return "unknown";
}

function trimOuterParentheses(expression: string): string {
  let value = expression.trim();
  for (;;) {
    if (!value.startsWith("(") || !value.endsWith(")")) return value;
    let depth = 0;
    let quote: "'" | '"' | undefined;
    let wraps = true;
    for (let index = 0; index < value.length; index++) {
      const char = value[index]!;
      if (quote) {
        if (char === quote && value[index - 1] !== "\\") quote = undefined;
        continue;
      }
      if (char === "'" || char === '"') {
        quote = char;
        continue;
      }
      if (char === "(") depth++;
      else if (char === ")") depth--;
      if (depth === 0 && index < value.length - 1) {
        wraps = false;
        break;
      }
    }
    if (!wraps) return value;
    value = value.slice(1, -1).trim();
  }
}

function splitBoolean(expression: string, operator: "and" | "or"): string[] {
  const value = trimOuterParentheses(expression);
  const parts: string[] = [];
  let depth = 0;
  let quote: "'" | '"' | undefined;
  let start = 0;
  for (let index = 0; index < value.length; index++) {
    const char = value[index]!;
    if (quote) {
      if (char === quote && value[index - 1] !== "\\") quote = undefined;
      continue;
    }
    if (char === "'" || char === '"') {
      quote = char;
      continue;
    }
    if (char === "(") {
      depth++;
      continue;
    }
    if (char === ")") {
      depth--;
      continue;
    }
    if (depth !== 0) continue;
    const rest = value.slice(index);
    const match = rest.match(new RegExp(`^\\s+${operator}\\s+`, "i"));
    if (!match) continue;
    parts.push(value.slice(start, index).trim());
    index += match[0].length - 1;
    start = index + 1;
  }
  if (!parts.length) return [value];
  parts.push(value.slice(start).trim());
  return parts.filter(Boolean);
}

export function policyExpressionGuarantees(
  expression: string | null,
  dimension: "ownership" | "tenant",
): boolean {
  if (!expression) return false;
  const value = trimOuterParentheses(expression);
  const or = splitBoolean(value, "or");
  if (or.length > 1)
    return or.every((part) => policyExpressionGuarantees(part, dimension));
  const and = splitBoolean(value, "and");
  if (and.length > 1)
    return and.some((part) => policyExpressionGuarantees(part, dimension));
  if (/^\\s*not\\b/i.test(value)) return false;
  const classification = classifyPolicyExpression(value);
  return dimension === "ownership"
    ? classification === "identity"
    : classification === "tenant";
}

export function policyGuarantees(
  snapshot: DatabaseSnapshot,
  schema: string,
  table: string,
  dimension: "ownership" | "tenant",
): boolean {
  const policies = snapshot.policies.filter(
    (policy) => policy.schema === schema && policy.table === table,
  );
  const expressionGuarantees = (policy: Policy) =>
    policyExpressionGuarantees(policy.using, dimension) ||
    policyExpressionGuarantees(policy.check, dimension);
  if (
    policies.some(
      (policy) =>
        policy.permissive === "RESTRICTIVE" && expressionGuarantees(policy),
    )
  )
    return true;
  const permissive = policies.filter(
    (policy) => policy.permissive === "PERMISSIVE",
  );
  return (
    permissive.length > 0 && permissive.every((policy) => expressionGuarantees(policy))
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

  for (const policy of snapshot.policies) {
    const classifications = [
      classifyPolicyExpression(policy.using),
      classifyPolicyExpression(policy.check),
    ];
    if (
      policy.permissive === "PERMISSIVE" &&
      policy.roles.some((role) => broadGrant(snapshot, role, broad)) &&
      classifications.includes("role-only")
    )
      add(
        `${policy.schema}.${policy.table}`,
        "REAPER-RLS-004",
        "RLS policy gates by role without row identity",
        "MEDIUM",
        "RLS",
        [
          `Policy ${policy.name} is permissive for a broad role.`,
          "The recognized predicate checks session role but no supported user/tenant row identity was established.",
        ],
        `role-only-policy:${policy.schema}:${policy.table}:${policy.name}`,
        "Bind row access to auth.uid() or a reviewed tenant claim when per-user or tenant isolation is required.",
      );
  }

  for (const table of snapshot.tables) {
    const policies = snapshot.policies.filter(
      (policy) =>
        policy.schema === table.schema &&
        policy.table === table.name &&
        policy.permissive === "PERMISSIVE" &&
        policy.roles.some((role) => broadGrant(snapshot, role, broad)),
    );
    const hasScoped = policies.some(
      (policy) =>
        policyExpressionGuarantees(policy.using, "ownership") ||
        policyExpressionGuarantees(policy.check, "ownership") ||
        policyExpressionGuarantees(policy.using, "tenant") ||
        policyExpressionGuarantees(policy.check, "tenant"),
    );
    const hasUnscopedAlternative = policies.some(
      (policy) =>
        !policyExpressionGuarantees(policy.using, "ownership") &&
        !policyExpressionGuarantees(policy.check, "ownership") &&
        !policyExpressionGuarantees(policy.using, "tenant") &&
        !policyExpressionGuarantees(policy.check, "tenant") &&
        !["constant-deny"].includes(classifyPolicyExpression(policy.using)) &&
        !["constant-deny"].includes(classifyPolicyExpression(policy.check)),
    );
    if (table.rls && hasScoped && hasUnscopedAlternative)
      add(
        `${table.schema}.${table.name}`,
        "REAPER-RLS-005",
        "Permissive policy alternatives prevent isolation proof",
        "MEDIUM",
        "RLS",
        [
          "At least one permissive policy has a recognized identity/tenant constraint, but another applicable permissive alternative does not.",
          "PostgreSQL OR-combines permissive policies, so a scoped policy alone does not prove row isolation.",
        ],
        `mixed-permissive:${table.schema}:${table.name}`,
        "Review all permissive policies together. Remove or restrict alternatives that can authorize rows without the intended ownership/tenant predicate.",
      );
  }

  for (const view of snapshot.views ?? []) {
    const grants = effectiveTableGrants(
      snapshot,
      view.schema,
      view.name,
    ).filter((grant) => grant.privilege === "SELECT");
    if (grants.length && !view.securityInvoker) {
      const rlsDependencies = (view.dependencies ?? []).filter((dependency) => {
        const [schema, name] = dependency.split(".", 2);
        return snapshot.tables.some(
          (table) => table.schema === schema && table.name === name && table.rls,
        );
      });
      add(
        `${view.schema}.${view.name}`,
        "REAPER-VIEW-001",
        "Broadly readable view does not use security_invoker",
        "HIGH",
        "Privileges",
        [
          `Effective broad SELECT through: ${[
            ...new Set(grants.map((grant) => grant.role)),
          ].join(", ")}`,
          ...(view.dependencies?.length
            ? [`Referenced relations: ${view.dependencies.join(", ")}`]
            : []),
          ...(rlsDependencies.length
            ? [
                `RLS-protected dependencies reached with owner-rights view semantics: ${rlsDependencies.join(", ")}`,
              ]
            : []),
          "The view executes with owner privileges unless security_invoker is enabled; review RLS behavior on referenced relations.",
        ],
        `view-security:${view.schema}:${view.name}`,
        "Prefer security_invoker=true for client-facing views when caller RLS/privileges should apply, and review the view definition and grants.",
      );
    }
  }

  for (const trigger of snapshot.triggers ?? []) {
    const fn = snapshot.functions.find(
      (candidate) =>
        candidate.schema === trigger.functionSchema &&
        candidate.name === trigger.functionName,
    );
    if (!fn?.securityDefiner || !unsafeSecurityDefinerSearchPath(fn)) continue;
    const grants = effectiveTableGrants(
      snapshot,
      trigger.schema,
      trigger.table,
    ).filter((grant) =>
      ["INSERT", "UPDATE", "DELETE"].includes(grant.privilege),
    );
    if (!grants.length) continue;
    add(
      `${trigger.schema}.${trigger.table}`,
      "REAPER-TRIGGER-001",
      "Broad DML can invoke SECURITY DEFINER trigger with unsafe search_path",
      "HIGH",
      "Privileges",
      [
        `Trigger ${trigger.name} invokes ${trigger.functionSchema}.${trigger.functionName}.`,
        `Effective broad DML through: ${[
          ...new Set(grants.map((grant) => `${grant.role}:${grant.privilege}`)),
        ].join(", ")}`,
        "The trigger function is SECURITY DEFINER and lacks a trusted function-local search_path.",
      ],
      `trigger-security:${trigger.schema}:${trigger.table}:${trigger.name}`,
      "Set a trusted function-local search_path, minimize table DML grants and review the trigger body for privilege-sensitive operations.",
    );
  }

  const storage = snapshot.tables.find(
    (table) => table.schema === "storage" && table.name === "objects",
  );
  if (storage) {
    const storagePolicies = snapshot.policies.filter(
      (policy) => policy.schema === "storage" && policy.table === "objects",
    );
    if (!storage.rls)
      add(
        "storage.objects",
        "REAPER-STORAGE-001",
        "Supabase Storage objects table has RLS disabled",
        "HIGH",
        "Supabase",
        ["storage.objects exists and row-level security is disabled."],
        "storage-no-rls",
        "Enable RLS on storage.objects and define reviewed bucket/object policies before exposing Storage to client roles.",
      );
    for (const policy of storagePolicies)
      if (
        policy.permissive === "PERMISSIVE" &&
        policy.roles.some((role) => broadGrant(snapshot, role, broad)) &&
        [
          classifyPolicyExpression(policy.using),
          classifyPolicyExpression(policy.check),
        ].includes("constant-open")
      )
        add(
          "storage.objects",
          "REAPER-STORAGE-002",
          "Supabase Storage policy permits all objects for a broad role",
          "HIGH",
          "Supabase",
          [
            `Policy ${policy.name} contains a constant-open predicate for roles ${policy.roles.join(", ")}.`,
          ],
          `storage-open:${policy.name}`,
          "Scope Storage policies to reviewed bucket, ownership or tenant predicates rather than a constant TRUE predicate.",
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
    if (!broadExecute.length) continue;

    const resource = `${fn.schema}.${fn.name}(${fn.identityArguments})`;
    const searchPath = configuredSearchPath(fn);
    if (unsafeSecurityDefinerSearchPath(fn))
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

    const dynamicSql =
      fn.definition &&
      /\bEXECUTE\b|\bformat\s*\(|\bquote_(?:ident|literal)\s*\(/i.test(
        fn.definition,
      );
    if (dynamicSql)
      add(
        resource,
        "REAPER-PG-002",
        "Broadly executable SECURITY DEFINER function builds dynamic SQL",
        "MEDIUM",
        "Privileges",
        [
          `SECURITY DEFINER owner: ${fn.owner}`,
          `Language: ${fn.language ?? "unknown"}`,
          `Effective broad EXECUTE through: ${broadExecute.join(", ")}`,
          "The function definition contains dynamic-SQL construction or execution primitives.",
        ],
        `security-definer-dynamic-sql:${resource}`,
        "Review all dynamic SQL for identifier/value allowlisting and parameterization, minimize EXECUTE grants, and keep a trusted function-local search_path.",
      );
  }

  return findings;
}
