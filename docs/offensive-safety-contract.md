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
- `runAttackJob` runs the engine through a runner-isolation provider. Standard mode uses a separate Node process with bounded IPC/output, filtered environment, a temporary working directory, an active deadline and cleanup grace. It is explicitly not an OS sandbox.
- Strict runner mode fails closed unless the injected provider declares process, filesystem, network and enforceable resource-limit isolation, and a persistent state directory is supplied. The provider is a trusted deployment component; production isolation still has to be enforced by the container/VM/runtime rather than merely declared in application code.
- Attack identities resolve environment or configured secret references through the `SecretProvider` boundary. Captured cookie values and captured values later used as identity tokens, cookies or headers are redacted from run results, reports, audit entries and graphs. Arbitrary captures not classified as credentials may still appear when explicitly used as resource evidence, so assessment reports remain sensitive. The built-in environment provider preserves CLI compatibility; deployment-provided providers can implement vault-backed secret retrieval and revocation. JavaScript cannot guarantee zeroing copies from process memory, and external vault lease enforcement remains deployment-dependent.

## Signed authorization scope

Strict deployments can set `attack.requireSignedScope: true` and provide an Ed25519 scope manifest together with a trusted-key source. The manifest binds the approved target origin, assessment identity, issuer/subject, environment, permissions, active/cleanup request caps, rate limit, expiry and global deadline.

The trust-store boundary validates key lifecycle metadata, including key identity, revocation and validity windows. Private signing keys are intentionally outside the repository and should be held by managed KMS/HSM or an equivalently reviewed signing service in production.

Strict execution consumes the signed scope nonce through an atomic replay store before active work begins. A successfully consumed nonce cannot be reused for the same protected authorization context. Strict workers additionally require persistent journal, replay and audit state so those controls survive the disposable worker process.

## Durable execution and audit state

Strict runs use write-ahead execution journaling for declared cleanup work. Recovery is bounded to cleanup operations that were persisted before interruption; REAPER does not invent recovery actions after a crash.

Audit events are stored as a persistent tamper-evident hash chain. Verification detects modified records and truncation within the persisted chain. For horizontally scaled production runners, journal, replay and audit storage must be backed by a reviewed shared durable service/database rather than per-runner local files.

## Commercial release gates

Repository-level foundations currently implemented and tested include:

- signed scope validation and atomic replay prevention;
- trusted-key lifecycle/revocation checks;
- persistent write-ahead journal and bounded crash recovery;
- tamper-evident audit chaining;
- organization/workspace/project authorization boundaries;
- PostgreSQL workspace RLS with cross-workspace adversarial integration coverage;
- signed data-only rule packs;
- strict runner capability contracts that fail closed;
- dependency audit, CycloneDX SBOM, SHA-256 package evidence and trusted tag attestation workflow;
- cross-platform CI and negative/adversarial fixtures.

Before claiming a complete hosted production platform, deployment-specific controls still require independent evidence: an OS/container isolation provider that actually enforces filesystem/network/CPU/RSS/PID boundaries, shared durable state for horizontally scaled runners, managed private-key and secret custody, hosted identity/API authorization, operational monitoring, incident-response readiness, deployment hardening review, independent penetration testing and a real-world pilot.

This file describes the enforced repository contract and the remaining deployment boundary; it is not a certification of any particular hosted environment.
