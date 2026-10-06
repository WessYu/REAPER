import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeDatabase } from "../dist/index.js";
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
