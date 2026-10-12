# Offensive validation safety contract

REAPER attack scenarios are for systems the operator is explicitly authorized to test. The authorization acknowledgement and reference in configuration are an audit declaration, not proof of ownership.

## Execution boundaries

- Scope is an explicit HTTP(S) origin; URL credentials, fragments, queries and path-bearing origins are rejected.
- Production attack scenarios cannot enable mutations.
- Mutating scenarios in local, preview or staging environments require cleanup steps.
- Request budgets, timeouts, rate limits and consecutive-server-error limits are mandatory operational controls, not suggestions.
- Synthetic identities and captured values must remain confined to the configured target and test environment.
- Never assume that an HTTP 200 alone proves cross-user data exposure: confirmation requires a known foreign-owned test resource and an explicit authorization expectation.
- A cleanup declaration is not proof that cleanup succeeded. Failed cleanup must remain visible as an incomplete run and require operator intervention.
- Prefer disposable test tenants, nonproduction data, least-privilege credentials and isolated runners.

## Commercial release gates

Before claiming production readiness: independent security assessment, SSRF/DNS-rebinding resistance for active requests, redirects and connection-level target pinning, secrets redaction tests, crash-safe cleanup, tenant-isolated execution, signed rules and artifacts, SBOM/provenance, auditable authorization and cancellation, documented incident response, and repeated cross-platform CI with negative/adversarial fixtures.

This file describes intended safety properties and release gates; it is not a certification that every listed control is implemented.
