# REAPER Platform

REAPER Platform is the hosted-control-plane foundation for the existing REAPER engine. It intentionally keeps the public CLI and engine usable on their own while adding multi-tenant orchestration, durable jobs and isolated commercial execution.

## Security architecture

```text
Dashboard
   |
Control Plane API
   |
PostgreSQL + RLS
   |
Durable job lease
   |
Dedicated worker host
   |
Hardened ephemeral runner container
   |
Authorized target
```

The API never contacts assessment targets. The dashboard never calls the REAPER engine directly. Only a worker-selected isolated runner may execute an active assessment.

### Trust boundaries

- **API**: authenticates HMAC-protected API keys, establishes workspace/principal context and relies on PostgreSQL RLS as defense in depth.
- **PostgreSQL**: stores organizations, workspaces, projects, assessments, runs, API keys, durable jobs, findings, audit records and replay state.
- **Worker**: leases jobs atomically through restricted `SECURITY DEFINER` functions. Run rows remain protected by workspace RLS.
- **Signer**: is external to REAPER Platform. The worker sends an authorization payload to an HTTPS signing service and receives only the signed scope plus its public verification key.
- **Runner**: is disposable and non-root. The host launches it with a read-only root filesystem, dropped Linux capabilities, `no-new-privileges`, CPU/RAM/PID limits and bounded tmpfs.
- **Persistent state**: each run receives a dedicated state directory for REAPER journal/replay/audit data. Horizontally scaled production deployments should replace host-local state with a reviewed shared durable implementation.

A private signing key must never be placed in this repository, in the API process, in the worker environment or in the runner container.

## Database roles

Migration `control-plane/002_platform.sql` creates two `NOLOGIN` group roles:

- `reaper_platform_api`
- `reaper_platform_worker`

Create separate LOGIN roles for deployed processes and grant each only the matching group role. Do not run the API or worker with the migration/admin database identity.

The migration command itself requires a privileged database URL because it creates schema objects, functions and group roles.

## Setup

Build the engine and platform:

```sh
npm ci --ignore-scripts
npm run build
npm run platform:build
```

Apply migrations using a privileged administrative database identity:

```sh
REAPER_PLATFORM_ADMIN_DATABASE_URL=postgres://... npm run platform:migrate
```

Bootstrap the first organization/workspace/admin API key exactly once:

```sh
REAPER_PLATFORM_ADMIN_DATABASE_URL=postgres://... \
REAPER_PLATFORM_API_KEY_PEPPER='<long-random-secret>' \
npm run platform:bootstrap
```

The bootstrap command prints the API key once. Store it in a secret manager. The database stores only its HMAC-SHA256 digest.

## API runtime

Required:

```text
REAPER_PLATFORM_DATABASE_URL
REAPER_PLATFORM_API_KEY_PEPPER
```

Optional:

```text
REAPER_PLATFORM_HOST=127.0.0.1
REAPER_PLATFORM_PORT=7338
```

Start:

```sh
npm run platform:serve
```

Main endpoints:

```text
GET    /health
GET    /dashboard
GET    /v1/me
GET    /v1/projects
POST   /v1/projects
GET    /v1/assessments
POST   /v1/assessments
GET    /v1/runs
POST   /v1/runs
GET    /v1/runs/:id
GET    /v1/runs/:id/findings
GET    /v1/runs/:id/audit
GET    /v1/api-keys
POST   /v1/api-keys
DELETE /v1/api-keys/:id
```

All `/v1` endpoints require:

```text
Authorization: Bearer reaper_live_...
```

The default bind address is loopback. Put a reviewed TLS reverse proxy or private service mesh in front of it before exposing it beyond the local host.

## Worker runtime

The worker uses a database login granted only `reaper_platform_worker`.

Required environment:

```text
REAPER_PLATFORM_DATABASE_URL
REAPER_PLATFORM_API_KEY_PEPPER
REAPER_PLATFORM_SIGNER_URL
REAPER_PLATFORM_SIGNER_TOKEN
REAPER_PLATFORM_SCOPE_PUBLIC_KEY
REAPER_PLATFORM_RUNNER_IMAGE
REAPER_PLATFORM_DOCKER_NETWORK
REAPER_PLATFORM_CONFIG_ROOT
REAPER_PLATFORM_STATE_ROOT
REAPER_PLATFORM_OUTPUT_ROOT
```

Optional:

```text
REAPER_PLATFORM_WORKER_ID
REAPER_PLATFORM_CONTAINER_UID
```

Start:

```sh
npm run platform:worker
```

The worker should run on a dedicated runner host. Do **not** containerize the worker by mounting `/var/run/docker.sock`; access to the Docker socket is effectively host-level control and would defeat the isolation boundary.

## Runner network

`REAPER_PLATFORM_DOCKER_NETWORK` must name a pre-created, reviewed network. Merely choosing a Docker network does not prove egress isolation.

Production needs an external network policy/firewall that restricts runner traffic to the authorized assessment path. REAPER's engine still enforces exact origins, address classes, DNS pinning/change detection, request budgets and signed authorization scope, but those application checks do not replace network-level isolation.

## Signer contract

The worker performs an HTTPS POST to `REAPER_PLATFORM_SIGNER_URL`:

```json
{
  "purpose": "reaper-authorization-scope-v1",
  "payload": {}
}
```

The service must return:

```json
{
  "keyId": "kms-key-version",
  "payload": {},
  "signature": "base64url-ed25519-signature"
}
```

The response payload must exactly match the requested payload. The runner then verifies the Ed25519 envelope again using `REAPER_PLATFORM_SCOPE_PUBLIC_KEY`. A managed KMS/HSM-backed service can implement this contract without exposing its private key to REAPER.

## Runner image

Build:

```sh
docker build -f platform/Dockerfile -t reaper-platform-runner:local .
```

The host-side worker additionally launches each run with:

- non-root numeric user;
- read-only root filesystem;
- all capabilities dropped;
- `no-new-privileges`;
- 512 MiB memory limit;
- 1 CPU;
- 128 PID limit;
- bounded `/tmp` tmpfs;
- read-only configuration mount;
- dedicated state/output mounts;
- explicit network selection.

The strict engine runner fails closed if its isolation capability contract or persistent state directory is missing.

## CI

Repository CI validates:

- dependency audit;
- lint and Prettier;
- root and platform TypeScript typechecking;
- root engine tests;
- platform unit tests;
- PostgreSQL integration tests serially;
- existing packed CLI behavior;
- hardened platform runner image build;
- existing SBOM/hash/release evidence.

## Production gates that remain external

Code can establish interfaces and fail-closed behavior, but it cannot certify its own hosting environment. Before a production/commercial maturity claim, obtain evidence for:

- actual firewall/egress enforcement on runner hosts;
- managed KMS/HSM key custody and signer access policy;
- managed secret storage and rotation;
- shared durable runner state if multiple workers are used;
- TLS/service identity and hosted SSO/OIDC if enabled;
- centralized logs, metrics and alerting;
- backup/restore and disaster recovery;
- incident-response runbooks and exercises;
- deployment hardening review;
- independent penetration test;
- real-world pilot.

Do not mark any of those as implemented merely because the repository contains an interface for them.
