import { test } from "node:test";
import assert from "node:assert/strict";
import { renderAttackRegression } from "../dist/index.js";

const config = {
  attack: {
    scope: {
      authorized: true,
      environment: "staging",
      allowedTargets: ["https://preview.example.test"],
    },
    identities: {
      a: { authEnv: "USER_A_TOKEN" },
      b: { authEnv: "USER_B_TOKEN" },
    },
    scenarios: [
      {
        name: "foreign order",
        kind: "bola",
        attackerIdentity: "a",
        ownerIdentity: "b",
        attack: {
          name: "read foreign order",
          path: "/api/orders/{{ORDER_ID}}",
        },
      },
      {
        name: "unrelated scenario",
        kind: "authorization",
        attackerIdentity: "a",
        attack: { name: "read admin", path: "/api/admin" },
      },
    ],
  },
};

test("regression generator keeps only confirmed scenarios and never embeds tokens", () => {
  const report = {
    version: "0.2.0",
    root: "https://preview.example.test",
    findings: [],
    diagnostics: [],
    graph: { nodes: [], edges: [] },
    metrics: {
      files: 0,
      routes: 1,
      sinks: 1,
      durationMs: 1,
      memoryBytes: 1,
    },
    coverage: { source: false, database: false, runtime: true },
    attack: {
      target: "https://preview.example.test",
      environment: "staging",
      startedAt: "2026-10-12T00:00:00.000Z",
      requestCount: 1,
      serverErrors: 0,
      scenarios: [
        {
          name: "foreign order",
          kind: "bola",
          status: "confirmed",
          findingId: "REAPER-ATTACK-001:test",
        },
        {
          name: "unrelated scenario",
          kind: "authorization",
          status: "passed",
        },
      ],
      audit: [],
    },
  };
  const source = renderAttackRegression(config, report);
  assert.match(source, /REAPER_ATTACK_TARGET/);
  assert.match(source, /foreign order/);
  assert.doesNotMatch(source, /unrelated scenario/);
  assert.match(source, /USER_A_TOKEN/);
  assert.doesNotMatch(source, /Bearer /);
});

test("regression generator refuses clean reports", () => {
  const report = {
    version: "0.2.0",
    root: "runtime",
    findings: [],
    diagnostics: [],
    graph: { nodes: [], edges: [] },
    metrics: {
      files: 0,
      routes: 0,
      sinks: 0,
      durationMs: 0,
      memoryBytes: 0,
    },
    coverage: { source: false, database: false, runtime: true },
    attack: {
      target: "http://127.0.0.1",
      environment: "local",
      startedAt: "2026-10-12T00:00:00.000Z",
      requestCount: 0,
      serverErrors: 0,
      scenarios: [{ name: "foreign order", kind: "bola", status: "passed" }],
      audit: [],
    },
  };
  assert.throws(() => renderAttackRegression(config, report), /no confirmed/);
});
