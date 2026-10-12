import { test } from "node:test";
import assert from "node:assert/strict";
import { validateAttackConfig, validateConfig } from "../dist/index.js";

const valid = {
  scope: {
    authorized: true,
    environment: "staging",
    allowedTargets: ["https://preview.example.test"],
    pathPrefixes: ["/api/"],
  },
  allowMutations: true,
  identities: {
    userA: { authEnv: "USER_A_TOKEN", role: "user", tenant: "a" },
    userB: { authEnv: "USER_B_TOKEN", role: "user", tenant: "b" },
  },
  scenarios: [
    {
      name: "cross-user order",
      kind: "bola",
      attackerIdentity: "userA",
      ownerIdentity: "userB",
      setup: [
        {
          name: "create owner order",
          path: "/api/orders",
          method: "POST",
          identity: "userB",
          body: { name: "reaper-synthetic" },
          capture: { RESOURCE_ID: "id" },
        },
      ],
      attack: {
        name: "read foreign order",
        path: "/api/orders/{{RESOURCE_ID}}",
        method: "GET",
        identity: "userA",
      },
      cleanup: [
        {
          name: "delete owner order",
          path: "/api/orders/{{RESOURCE_ID}}",
          method: "DELETE",
          identity: "userB",
        },
      ],
      denyStatuses: [401, 403, 404],
    },
  ],
};

test("attack config validates explicit authorized stateful scenarios", () => {
  assert.deepEqual(validateAttackConfig(valid).scope.environment, "staging");
  assert.ok(validateConfig({ attack: valid }).attack);
});

test("attack config requires explicit authorization and production opt-in", () => {
  assert.throws(
    () =>
      validateAttackConfig({
        ...valid,
        scope: { ...valid.scope, authorized: false },
      }),
    /authorized/,
  );
  assert.throws(
    () =>
      validateAttackConfig({
        ...valid,
        scope: {
          authorized: true,
          environment: "production",
          allowedTargets: ["https://prod.example.test"],
        },
      }),
    /allowProduction/,
  );
});

test("attack config rejects unscoped mutation and unknown identities", () => {
  assert.throws(
    () => validateAttackConfig({ ...valid, allowMutations: false }),
    /allowMutations/,
  );
  assert.throws(
    () =>
      validateAttackConfig({
        ...valid,
        scenarios: [
          {
            ...valid.scenarios[0],
            attackerIdentity: "missing",
          },
        ],
      }),
    /attackerIdentity/,
  );
});

test("production attack mode requires expiring authorization and separate mutation consent", () => {
  const production = {
    ...valid,
    scope: {
      authorized: true,
      environment: "production",
      allowedTargets: ["https://prod.example.test"],
      allowProduction: true,
      authorizationId: "CHANGE-1234",
      expiresAt: "2099-01-01T00:00:00.000Z",
    },
  };
  assert.throws(
    () => validateAttackConfig(production),
    /allowProductionMutations/,
  );
  assert.doesNotThrow(() =>
    validateAttackConfig({
      ...production,
      scope: {
        ...production.scope,
        allowProductionMutations: true,
      },
      maxMutationRequests: 3,
      rateLimitPerSecond: 2,
    }),
  );
  assert.throws(
    () =>
      validateAttackConfig({
        ...production,
        scope: {
          ...production.scope,
          allowProductionMutations: true,
        },
        maxMutationRequests: 6,
      }),
    /cannot exceed 5/,
  );
});

