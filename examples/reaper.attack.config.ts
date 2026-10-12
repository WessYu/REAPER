export default {
  attack: {
    scope: {
      authorized: true,
      authorizationId: "EXAMPLE-AUTHORIZATION-ID",
      expiresAt: "2099-01-01T00:00:00.000Z",
      environment: "staging",
      allowedTargets: ["https://preview.example.test"],
      pathPrefixes: ["/api/"],
    },
    maxRequests: 30,
    maxMutationRequests: 6,
    maxUploadBytes: 65536,
    timeoutMs: 5000,
    rateLimitPerSecond: 3,
    maxServerErrors: 3,
    allowMutations: true,
    identities: {
      userA: {
        authEnv: "REAPER_USER_A_TOKEN",
        role: "user",
        privilegeLevel: 10,
        tenant: "tenant-a",
      },
      userB: {
        authEnv: "REAPER_USER_B_TOKEN",
        role: "user",
        privilegeLevel: 10,
        tenant: "tenant-b",
      },
      admin: {
        authEnv: "REAPER_ADMIN_TOKEN",
        role: "admin",
        privilegeLevel: 90,
        tenant: "tenant-a",
      },
    },
    scenarios: [
      {
        name: "cross-user order access",
        kind: "bola",
        attackerIdentity: "userA",
        ownerIdentity: "userB",
        resource: "order",
        setup: [
          {
            name: "create owner order",
            path: "/api/orders",
            method: "POST",
            identity: "userB",
            body: { label: "reaper-synthetic" },
            expectStatus: 201,
            capture: { RESOURCE_ID: "id" },
          },
        ],
        attack: {
          name: "read foreign order",
          path: "/api/orders/{{RESOURCE_ID}}",
          method: "GET",
        },
        cleanup: [
          {
            name: "delete owner order",
            path: "/api/orders/{{RESOURCE_ID}}",
            method: "DELETE",
            identity: "userB",
            expectStatus: 204,
          },
        ],
        denyStatuses: [401, 403, 404],
      },
      {
        name: "regular user cannot read admin state",
        kind: "privilege",
        attackerIdentity: "userA",
        ownerIdentity: "admin",
        attack: {
          name: "read admin endpoint",
          path: "/api/admin/state",
          method: "GET",
        },
        expect: { statuses: [401, 403, 404] },
      },
    ],
  },
};
