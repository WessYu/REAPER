# Offensive validation safety contract

REAPER attack scenarios are for systems the operator is explicitly authorized to test. The authorization acknowledgement and reference in configuration are an audit declaration, not proof of ownership.

## Execution boundaries

- Scope is an explicit HTTP(S) origin; URL credentials, fragments, queries and path-bearing origins are rejected.
- Production authorization requires a future expiry and production attack scenarios cannot enable mutations.
- RFC1918/ULA-style private targets require an explicit `allowPrivateNetwork` opt-in; loopback remains usable for local test harnesses. Link-local, unspecified, multicast and reserved infrastructure addresses are blocked even with private-network opt-in.
- Mutating scenarios in local, preview or staging environments require cleanup steps.
- Active requests and cleanup have separate bounded budgets. Timeouts, rate limits and consecutive-server-error limits are mandatory operational controls, not suggestions.
- Synthetic identities and captured values must remain confined to the configured target and test environment. Bearer tokens, session-cookie values and custom-header secrets stay in environment/in-memory state and must not be emitted in findings or audit events.
- Never assume that a status anomaly alone proves cross-user data exposure: confirmation requires a known foreign-owned test resource and an explicit authorization expectation, defaults to HTTP 2xx confirmation responses, and can require JSON field proof bound to the known resource.
- Outbound connections are pinned to the initially approved DNS resolution and DNS changes terminate active execution before a new address is contacted.
- A cleanup declaration is not proof that cleanup succeeded. Cleanup receives a bounded best-effort attempt after cancellation, and failed cleanup must remain visible as an incomplete run that requires operator intervention.
- Prefer disposable test tenants, nonproduction data, least-privilege credentials and isolated runners.
- `runAttackJob` runs the engine in a child process. Its active deadline sends cancellation first; declared cleanup gets a separate grace period capped at 60 seconds, followed by a force kill. Cleanup remains best effort. `runAttack` and the CLI still execute in-process.
- Attack identities resolve environment or configured secret references through the `SecretProvider` boundary. The built-in environment provider preserves CLI compatibility; deployment-provided providers can implement revocation. Secret values are not part of run results, reports, audit entries or journal metadata. JavaScript cannot guarantee zeroing copies from process memory, and external vault lease enforcement remains deployment-dependent.

Strict deployments can set `attack.requireSignedScope: true` and call `runAttack` with `scopeManifest` and `trustedScopeKeys`. The Ed25519 manifest binds exact target origins, assessment ID, issuer, subject, environment, permissions, expiry, request/cleanup/rate limits and a global deadline. Scope validity is limited to 24 hours. The CLI accepts manifest JSON and a trusted PEM public key through `REAPER_SCOPE_MANIFEST` and `REAPER_SCOPE_PUBLIC_KEY`. Provision the public key through a trusted channel and keep its private key outside the repository. The nonce is signed as audit context; REAPER does not yet maintain replay prevention or key revocation.

## Commercial release gates

Before claiming production readiness: independent security assessment of the pinned transport and network-scope controls, crash-safe cleanup across process termination, isolated multi-tenant execution, signed rules and artifacts, SBOM/provenance, auditable authorization and cancellation, documented incident response, secrets-redaction review, and repeated cross-platform CI with negative/adversarial fixtures.

This file describes intended safety properties and release gates; it is not a certification that every listed control is implemented.
