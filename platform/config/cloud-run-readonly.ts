export default {
  attack: {
    allowedTargets: ["https://placeholder.invalid"],
    authorization: {
      acknowledged: true,
      reference: "placeholder-assessment",
      environment: "staging",
    },
    maxRequests: 8,
    maxCleanupRequests: 4,
    timeoutMs: 5000,
    rateLimitPerSecond: 2,
    maxConsecutiveServerErrors: 3,
    allowMutations: false,
    allowPrivateNetwork: false,
    requireSignedScope: true,
    scenarios: [
      {
        id: "readonly-boundary",
        title: "Authorized read-only boundary probe",
        dimension: "business-logic",
        severity: "INFO",
        steps: [
          {
            name: "root endpoint remains within the declared response policy",
            path: "/",
            method: "GET",
            expect: {
              allowedStatuses: [200, 204, 401, 403, 404],
            },
          },
        ],
      },
    ],
  },
};
