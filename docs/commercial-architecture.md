# Commercial architecture boundaries

REAPER is currently a single Node.js package and local CLI/library. The current repository is MIT licensed; code already distributed under MIT remains available under those terms. Changing the license later cannot retract those grants.

## Current boundaries

- `src/` contains analysis, database inspection, runtime verification, attack execution, reporting, the local review server, and the trusted Rule SDK.
- `bin/reaper.js` is the npm CLI entry point.
- `.github/workflows/ci.yml` tests Node 22/24, Windows, PostgreSQL integration, npm packaging, and installed CLI behavior.
- `reaper serve` binds to loopback and is not a hosted multi-user control plane.
- The existing CLI and `runAttack` API execute in their calling process. The new `runAttackJob` API launches the trusted engine in a separate Node child process with a validated job, a temporary working directory, a filtered environment, a V8 heap limit, an active deadline, bounded cleanup grace, and bounded IPC/output. This is a process boundary, not an OS sandbox: the worker retains the caller's filesystem permissions, Node's heap limit does not cap total RSS, and network egress/CPU scheduling require deployment controls. Strict attack mode can verify an Ed25519 authorization scope, but trusted key distribution and replay prevention are external. Signed data-only literal rule packs are supported; the JavaScript Rule SDK remains trusted local code. There is no durable journal, hosted secret vault, or multi-tenant persistence model.

## Possible product split

| Product boundary               | Appropriate contents                                                                                                                                | Boundary required before claiming it                                                                                                                                |
| ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **REAPER Community**           | Existing MIT analysis engine, CLI, local reports, documented local Rule SDK                                                                         | Keep the existing MIT grant intact; define maintained release and support policy                                                                                    |
| **REAPER Commercial Engine**   | Additional licensed attack scenarios, signed assessment scope, bounded child-process runner API, durable cleanup journal, managed signed rule packs | Stable versioned runner protocol, OS-enforced isolation, scope verification, independent security review, artifact signing, and explicit license terms for new code |
| **REAPER Enterprise Platform** | Organization/workspace/project, assessment history, delegated access, policy administration, audit retention, integrations                          | Tenant-scoped persistence plus RLS and API authorization, identity lifecycle, operational isolation, incident response, deployment hardening, and external testing  |

These are possible repository boundaries, not implemented packages or products. A future private repository can consume the public package through a versioned API. Commercial-only code should be newly authored or contributed under terms that permit that distribution; it must not copy or relabel previously published MIT code as closed source.

## Migration direction

Preserve the current tree until a tested boundary is needed. A practical sequence is to harden the versioned job protocol and child-process runner with deployment-enforced isolation, then add a durable cleanup journal and control-plane components behind workspace-scoped interfaces. Keep the local CLI usable without the platform. Any future container isolation must explicitly avoid privileged mode, Docker socket mounts, and broad host mounts; resource and network controls must be verified by the deployment platform.

No architecture description here implies isolation or hosted multi-tenancy today. Commercial maturity also requires independent penetration testing, architecture review, deployment hardening review, incident-response readiness, monitoring, and a real-world pilot.
