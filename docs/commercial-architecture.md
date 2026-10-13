# Commercial architecture boundaries

REAPER is currently a single Node.js package and local CLI/library. The current repository is MIT licensed; code already distributed under MIT remains available under those terms. Changing the license later cannot retract those grants.

## Current boundaries

- `src/` contains analysis, database inspection, runtime verification, attack execution, reporting, the local review server, and the trusted Rule SDK.
- `bin/reaper.js` is the npm CLI entry point.
- `.github/workflows/ci.yml` tests Node 22/24, Windows, PostgreSQL integration, npm packaging, and installed CLI behavior.
- `reaper serve` binds to loopback and is not a hosted multi-user control plane.
- The existing CLI and direct `runAttack` API execute in their calling process. `runAttackJob` launches the trusted engine through a runner-isolation provider with a validated job, filtered environment, bounded IPC/output, deadline and cleanup grace. Standard mode uses a child process and is explicitly not an OS sandbox. Strict mode fails closed unless the injected provider advertises process, filesystem, network and enforceable resource-limit capabilities and a persistent state directory is supplied.
- Strict commercial runs can verify an Ed25519 authorization scope, consume its nonce through an atomic replay store, persist write-ahead cleanup intent in an execution journal, maintain a tamper-evident audit chain, and recover only previously declared cleanup operations after interruption. The built-in filesystem providers are suitable for the local foundation; shared/distributed production deployments still need a reviewed durable backend.
- A control-plane schema now models organizations, workspaces, membership, projects, assessments, runs, findings, audit events and consumed scope nonces. PostgreSQL RLS plus an application authorization boundary provide defense in depth for workspace isolation. This is a persistence foundation, not a hosted API or identity service.
- Signed data-only literal rule packs are supported and can be verified through a key-lifecycle trust store. The JavaScript Rule SDK remains trusted local code. Private signing keys, managed KMS/HSM integration, external secret vaulting and OS-enforced sandboxing remain deployment responsibilities.

## Possible product split

| Product boundary               | Appropriate contents                                                                                                                                           | Boundary required before claiming it                                                                                                                                                  |
| ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **REAPER Community**           | Existing MIT analysis engine, CLI, local reports, documented local Rule SDK                                                                                    | Keep the existing MIT grant intact; define maintained release and support policy                                                                                                      |
| **REAPER Commercial Engine**   | Additional licensed attack scenarios, signed assessment scope, strict runner contract, crash-recovery journal, tamper-evident audit, managed signed rule packs | Reviewed OS-enforced isolation provider, managed key/secret infrastructure, independent security review, artifact signing, and explicit license terms for new code                    |
| **REAPER Enterprise Platform** | Organization/workspace/project, assessment history, delegated access, tenant-scoped persistence, audit retention, integrations                                 | Hosted identity/API layer, reviewed RLS deployment, shared durable replay/journal/audit backend, operational isolation, incident response, deployment hardening, and external testing |

These are possible repository boundaries, not implemented packages or products. A future private repository can consume the public package through a versioned API. Commercial-only code should be newly authored or contributed under terms that permit that distribution; it must not copy or relabel previously published MIT code as closed source.

## Migration direction

Preserve the current tree until a tested package boundary is needed. The repository now contains the versioned job/runner boundary, durable local journal/replay/audit stores, a workspace authorization model, and a PostgreSQL control-plane/RLS foundation. Keep the local CLI usable without the platform. A production commercial deployment must replace the standard process boundary with a reviewed strict isolation provider and should move shared state into a durable service/database appropriate for multiple runners. Any container isolation must explicitly avoid privileged mode, Docker socket mounts, and broad host mounts; resource and network controls must be verified by the deployment platform.

No architecture description here implies isolation or hosted multi-tenancy today. Commercial maturity also requires independent penetration testing, architecture review, deployment hardening review, incident-response readiness, monitoring, and a real-world pilot.
