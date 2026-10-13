# Commercial architecture boundaries

REAPER is currently a single Node.js package and local CLI/library. The current repository is MIT licensed; code already distributed under MIT remains available under those terms. Changing the license later cannot retract those grants.

## Current boundaries

- `src/` contains analysis, database inspection, runtime verification, attack execution, reporting, the local review server, and the trusted Rule SDK.
- `bin/reaper.js` is the npm CLI entry point.
- `.github/workflows/ci.yml` tests Node 22/24, Windows, PostgreSQL integration, npm packaging, and installed CLI behavior.
- `reaper serve` binds to loopback and is not a hosted multi-user control plane.
- Active execution currently runs in the CLI/library process. Strict attack mode can verify an Ed25519 authorization scope, but trusted key distribution and replay prevention are external. There is no OS sandbox, durable journal, secret lease provider, multi-tenant persistence model, or signed rule-pack loader.

## Possible product split

| Product boundary               | Appropriate contents                                                                                                                    | Boundary required before claiming it                                                                                                                               |
| ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **REAPER Community**           | Existing MIT analysis engine, CLI, local reports, documented local Rule SDK                                                             | Keep the existing MIT grant intact; define maintained release and support policy                                                                                   |
| **REAPER Commercial Engine**   | Additional licensed attack scenarios, signed assessment scope, isolated runner integration, durable cleanup journal, managed rule packs | Stable versioned runner protocol, scope verification, independent security review, artifact signing, and explicit license terms for new code                       |
| **REAPER Enterprise Platform** | Organization/workspace/project, assessment history, delegated access, policy administration, audit retention, integrations              | Tenant-scoped persistence plus RLS and API authorization, identity lifecycle, operational isolation, incident response, deployment hardening, and external testing |

These are possible repository boundaries, not implemented packages or products. A future private repository can consume the public package through a versioned API. Commercial-only code should be newly authored or contributed under terms that permit that distribution; it must not copy or relabel previously published MIT code as closed source.

## Migration direction

Preserve the current tree until a tested boundary is needed. A practical sequence is to extract a versioned protocol and engine API, then implement a runner that consumes immutable jobs, then add persistence and control-plane components behind workspace-scoped interfaces. Keep the local CLI usable without the platform. Any future container isolation must explicitly avoid privileged mode, Docker socket mounts, and broad host mounts; resource and network controls must be verified by the deployment platform.

No architecture description here implies isolation or hosted multi-tenancy today. Commercial maturity also requires independent penetration testing, architecture review, deployment hardening review, incident-response readiness, monitoring, and a real-world pilot.
