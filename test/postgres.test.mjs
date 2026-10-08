import { test } from "node:test";
import assert from "node:assert/strict";
import {
  analyzeDatabase,
  policyExpressionGuarantees,
  policyGuarantees,
} from "../dist/index.js";
const table = {
  schema: "public",
  name: "orders",
  owner: "owner",
  rls: true,
  force: false,
};
const policy = {
  schema: "public",
  table: "orders",
  name: "owner_read",
  roles: ["authenticated"],
  command: "SELECT",
  permissive: "PERMISSIVE",
  using: "user_id = auth.uid()",
  check: null,
};
const snapshot = (overrides = {}) => ({
  tables: [table],
  policies: [policy],
  grants: [],
  roles: [],
  memberships: [],
  schemaGrants: [],
  columnGrants: [],
  functions: [],
  views: [],
  triggers: [],
  serverVersion: "test",
  limitations: [],
  ...overrides,
});
test("RLS missing only flags broadly granted tables", () => {
  assert.equal(
    analyzeDatabase(snapshot({ tables: [{ ...table, rls: false }] })).length,
    0,
  );
  const result = analyzeDatabase(
    snapshot({
      tables: [{ ...table, rls: false }],
      grants: [
        {
          schema: "public",
          table: "orders",
          role: "anon",
          privilege: "SELECT",
        },
      ],
    }),
  );
  assert.equal(result[0].ruleId, "REAPER-RLS-001");
});
test("no-policy RLS is default-deny information, not exposure", () => {
  const result = analyzeDatabase(snapshot({ policies: [] }));
  assert.equal(result[0].ruleId, "REAPER-RLS-002");
  assert.equal(result[0].severity, "INFO");
});
test("constant permissive policy is candidate, restrictive TRUE is not flagged", () => {
  assert.equal(analyzeDatabase(snapshot()).length, 0);
  const p = { ...policy, using: "(true)" };
  assert.equal(
    analyzeDatabase(snapshot({ policies: [p] }))[0].ruleId,
    "REAPER-RLS-003",
  );
  assert.equal(
    analyzeDatabase(
      snapshot({ policies: [{ ...p, permissive: "RESTRICTIVE" }] }),
    ).length,
    0,
  );
});
test("WITH CHECK and PUBLIC dangerous privilege are separately represented", () => {
  const result = analyzeDatabase(
    snapshot({
      policies: [{ ...policy, using: null, check: "true" }],
      grants: [
        {
          schema: "public",
          table: "orders",
          role: "PUBLIC",
          privilege: "TRUNCATE",
        },
      ],
    }),
  );
  assert.deepEqual(
    result.map((f) => f.ruleId),
    ["REAPER-RLS-003", "REAPER-PRIV-001"],
  );
});
test("owner privileges alone are not called excessive", () =>
  assert.equal(
    analyzeDatabase(
      snapshot({
        grants: [
          {
            schema: "public",
            table: "orders",
            role: "owner",
            privilege: "TRUNCATE",
          },
        ],
      }),
    ).length,
    0,
  ));

test("inherited broad roles are included in effective table privileges", () => {
  const result = analyzeDatabase(
    snapshot({
      tables: [{ ...table, rls: false }],
      roles: [
        {
          name: "anon",
          superuser: false,
          bypassRls: false,
          login: true,
          inherit: true,
        },
        {
          name: "app_reader",
          superuser: false,
          bypassRls: false,
          login: false,
          inherit: true,
        },
      ],
      memberships: [{ member: "anon", role: "app_reader", adminOption: false }],
      grants: [
        {
          schema: "public",
          table: "orders",
          role: "app_reader",
          privilege: "SELECT",
        },
      ],
    }),
  );
  assert.ok(result.some((f) => f.ruleId === "REAPER-RLS-001"));
});

test("broad schema CREATE and role bypass privileges are explicit findings", () => {
  const result = analyzeDatabase(
    snapshot({
      roles: [
        {
          name: "authenticated",
          superuser: false,
          bypassRls: true,
          login: true,
          inherit: true,
        },
      ],
      schemaGrants: [
        { schema: "public", role: "authenticated", privilege: "CREATE" },
      ],
    }),
  );
  assert.ok(result.some((f) => f.ruleId === "REAPER-PRIV-002"));
  assert.ok(result.some((f) => f.ruleId === "REAPER-PRIV-003"));
});

test("SECURITY DEFINER review requires broad execute and unsafe search_path", () => {
  const unsafe = {
    schema: "public",
    name: "dangerous_rpc",
    identityArguments: "id uuid",
    owner: "owner",
    securityDefiner: true,
    config: null,
    executeRoles: ["PUBLIC"],
  };
  assert.ok(
    analyzeDatabase(snapshot({ functions: [unsafe] })).some(
      (f) => f.ruleId === "REAPER-PG-001",
    ),
  );
  assert.equal(
    analyzeDatabase(
      snapshot({
        functions: [
          {
            ...unsafe,
            config: ["search_path=pg_catalog, app_private"],
          },
        ],
      }),
    ).filter((f) => f.ruleId === "REAPER-PG-001").length,
    0,
  );
  assert.equal(
    analyzeDatabase(
      snapshot({
        functions: [{ ...unsafe, executeRoles: ["internal_admin"] }],
      }),
    ).filter((f) => f.ruleId === "REAPER-PG-001").length,
    0,
  );
});

test("symbolic RLS classification distinguishes identity, tenant and role-only policies", async () => {
  const { classifyPolicyExpression } = await import("../dist/index.js");
  assert.equal(classifyPolicyExpression("user_id = auth.uid()"), "identity");
  assert.equal(
    classifyPolicyExpression("(auth.jwt() ->> 'tenant_id') = tenant_id"),
    "tenant",
  );
  assert.equal(
    classifyPolicyExpression("auth.role() = 'authenticated'"),
    "role-only",
  );
});

test("broad client-facing owner-rights views are review findings", () => {
  const result = analyzeDatabase(
    snapshot({
      views: [
        {
          schema: "public",
          name: "order_summary",
          owner: "owner",
          materialized: false,
          securityInvoker: false,
          definition: "SELECT * FROM orders",
        },
      ],
      grants: [
        {
          schema: "public",
          table: "order_summary",
          role: "authenticated",
          privilege: "SELECT",
        },
      ],
    }),
  );
  assert.ok(result.some((finding) => finding.ruleId === "REAPER-VIEW-001"));
});

test("unsafe SECURITY DEFINER trigger is correlated with broad table DML", () => {
  const result = analyzeDatabase(
    snapshot({
      functions: [
        {
          schema: "public",
          name: "audit_order",
          identityArguments: "",
          owner: "owner",
          securityDefiner: true,
          config: null,
          executeRoles: ["owner"],
        },
      ],
      triggers: [
        {
          schema: "public",
          table: "orders",
          name: "orders_audit",
          functionSchema: "public",
          functionName: "audit_order",
          enabled: "O",
        },
      ],
      grants: [
        {
          schema: "public",
          table: "orders",
          role: "authenticated",
          privilege: "UPDATE",
        },
      ],
    }),
  );
  assert.ok(result.some((finding) => finding.ruleId === "REAPER-TRIGGER-001"));
});

test("Supabase Storage posture is represented explicitly", () => {
  const result = analyzeDatabase(
    snapshot({
      tables: [
        table,
        {
          schema: "storage",
          name: "objects",
          owner: "owner",
          rls: false,
          force: false,
        },
      ],
      policies: [policy],
    }),
  );
  assert.ok(result.some((finding) => finding.ruleId === "REAPER-STORAGE-001"));
});

test("policy expression composition requires every OR branch to preserve isolation", () => {
  assert.equal(
    policyExpressionGuarantees(
      "(user_id = auth.uid()) OR (owner_id = auth.uid())",
      "ownership",
    ),
    true,
  );
  assert.equal(
    policyExpressionGuarantees(
      "(user_id = auth.uid()) OR (published = true)",
      "ownership",
    ),
    false,
  );
  assert.equal(
    policyExpressionGuarantees(
      "(organization_id = (auth.jwt()->>'organization_id')) AND active = true",
      "tenant",
    ),
    true,
  );
});

test("policyGuarantees respects PostgreSQL permissive OR composition", () => {
  const base = snapshot({
    policies: [
      {
        schema: "public",
        table: "orders",
        name: "owner",
        roles: ["authenticated"],
        command: "SELECT",
        permissive: "PERMISSIVE",
        using: "user_id = auth.uid()",
        check: null,
      },
      {
        schema: "public",
        table: "orders",
        name: "published",
        roles: ["authenticated"],
        command: "SELECT",
        permissive: "PERMISSIVE",
        using: "published = true",
        check: null,
      },
    ],
  });
  assert.equal(policyGuarantees(base, "public", "orders", "ownership"), false);
  base.policies[1].permissive = "RESTRICTIVE";
  base.policies[1].using = "user_id = auth.uid()";
  assert.equal(policyGuarantees(base, "public", "orders", "ownership"), true);
});

