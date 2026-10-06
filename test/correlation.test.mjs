import { test } from "node:test";
import assert from "node:assert/strict";
import { correlateSourceDatabase } from "../dist/index.js";

const source = {
  version: "0.1.0",
  root: "/app",
  findings: [],
  diagnostics: [],
  graph: {
    nodes: [
      { id: "route:GET /orders", kind: "route", label: "GET /orders" },
      {
        id: "query:src/orders.ts:10:5",
        kind: "query",
        label: "supabase.select",
      },
      { id: "resource:orders", kind: "resource", label: "orders" },
    ],
    edges: [
      {
        from: "route:GET /orders",
        to: "query:src/orders.ts:10:5",
        relation: "calls",
      },
      {
        from: "query:src/orders.ts:10:5",
        to: "resource:orders",
        relation: "accesses",
      },
    ],
  },
  metrics: {
    files: 1,
    routes: 1,
    sinks: 1,
    durationMs: 1,
    memoryBytes: 1,
  },
  coverage: { source: true, database: false, runtime: false },
};

const snapshot = (overrides = {}) => ({
  tables: [
    {
      schema: "public",
      name: "orders",
      rls: false,
      force: false,
      owner: "owner",
    },
  ],
  policies: [],
  roles: [
    {
      name: "authenticated",
      superuser: false,
      bypassRls: false,
      login: false,
      inherit: true,
    },
  ],
  memberships: [],
  grants: [
    {
      schema: "public",
      table: "orders",
      role: "authenticated",
      privilege: "SELECT",
    },
  ],
  schemaGrants: [],
  columnGrants: [],
  functions: [],
  serverVersion: "test",
  limitations: [],
  ...overrides,
});

test("Supabase source/database correlation requires both a matching grant and missing RLS", () => {
  const findings = correlateSourceDatabase(source, snapshot());
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "REAPER-SUPA-002");
  assert.equal(findings[0].confidence, "HIGH");
  assert.equal(findings[0].route, "GET /orders");

  assert.equal(
    correlateSourceDatabase(
      source,
      snapshot({
        tables: [
          {
            schema: "public",
            name: "orders",
            rls: true,
            force: false,
            owner: "owner",
          },
        ],
      }),
    ).length,
    0,
  );

  assert.equal(
    correlateSourceDatabase(source, snapshot({ grants: [] })).length,
    0,
  );
});

test("Supabase correlation follows inherited client-role grants", () => {
  const findings = correlateSourceDatabase(
    source,
    snapshot({
      roles: [
        {
          name: "authenticated",
          superuser: false,
          bypassRls: false,
          login: false,
          inherit: true,
        },
        {
          name: "reader",
          superuser: false,
          bypassRls: false,
          login: false,
          inherit: true,
        },
      ],
      memberships: [
        { member: "authenticated", role: "reader", adminOption: false },
      ],
      grants: [
        {
          schema: "public",
          table: "orders",
          role: "reader",
          privilege: "SELECT",
        },
      ],
    }),
  );
  assert.equal(findings.length, 1);
  assert.match(findings[0].description, /RLS is disabled/);
});
