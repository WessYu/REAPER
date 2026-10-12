# Offensive validation safety contract

REAPER attack scenarios are for systems the operator is explicitly authorized to test. The authorization acknowledgement and reference in configuration are an audit declaration, not proof of ownership.

## Execution boundaries

- Scope is an explicit HTTP(S) origin; URL credentials, fragments, queries and path-bearing origins are rejected.
- Production authorization requires a future expiry and production attack scenarios cannot enable mutations.
- Non-loopback private/link-local targets require an explicit `allowPrivateNetwork` opt-in; loopback remains usable for local test harnesses.
- Mutating scenarios in local, preview or staging environments require cleanup steps.
- Request budgets, timeouts, rate limits and consecutive-server-error limits are mandatory operational controls, not suggestions.
- Synthetic identities and captured values must remain confined to the configured target and test environment. Bearer tokens, session-cookie values and custom-header secrets stay in environment/in-memory state and must not be emitted in findings or audit events.
- Never assume that a status anomaly alone proves cross-user data exposure: confirmation requires a known foreign-owned test resource and an explicit authorization expectation, defaults to HTTP 2xx confirmation responses, and can require JSON field proof bound to the known resource.
- A cleanup declaration is not proof that cleanup succeeded. Failed cleanup must remain visible as an incomplete run and require operator intervention.
- Prefer disposable test tenants, nonproduction data, least-privilege credentials and isolated runners.

## Commercial release gates

Before claiming production readiness: independent security assessment, connection-level SSRF/DNS-rebinding defenses beyond the current DNS-change/private-network guards, crash-safe cleanup, isolated multi-tenant execution, signed rules and artifacts, SBOM/provenance, auditable authorization and cancellation, documented incident response, secrets-redaction review, and repeated cross-platform CI with negative/adversarial fixtures.

This file describes intended safety properties and release gates; it is not a certification that every listed control is implemented.
