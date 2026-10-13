# Free staging runner

REAPER has a zero-fixed-cost staging execution path for authorized, read-only
assessments.

```text
REAPER dashboard / Supabase Edge
        |
PostgreSQL durable job
        |
GitHub Actions schedule / workflow_dispatch
        |
GitHub OIDC identity
        |
GitHub-hosted ephemeral runner
        |
bounded read-only REAPER probe
        |
authorized HTTPS staging target
        |
report + normalized findings + audit
        |
Supabase
```

This path requires no Google Cloud resources, no VM, no GitHub PAT, no database
password in GitHub Actions, and no configured GitHub Actions secret.

## Safety profile

The free runner is intentionally narrower than REAPER's commercial strict
execution plane. It only leases jobs that satisfy all of these conditions:

- environment is `preview` or `staging`;
- target is an exact HTTPS origin;
- config is `free-readonly.ts`;
- permission set is exactly `["read"]`;
- at most 8 requests;
- at most 1 cleanup request budget;
- at most 2 requests per second;
- deadline at most 60 seconds.

The executed free scenario is compiled into the runner and performs a single
unauthenticated `GET /` probe. It does not load target-controlled code, use
credentials, allow mutations, or allow private-network targets.

The engine's DNS pinning, private-address checks, request budgets and timeout
remain active.

## Authentication

GitHub Actions requests an OIDC token with audience `reaper-staging`.

The Supabase gateway verifies:

- issuer: `https://token.actions.githubusercontent.com`;
- audience: `reaper-staging`;
- repository: `WessYu/REAPER`;
- ref: `refs/heads/main`;
- exact workflow ref:
  `WessYu/REAPER/.github/workflows/free-runner.yml@refs/heads/main`;
- event: scheduled or manual workflow dispatch;
- JWT signature against GitHub's published JWKS;
- token timing constraints.

The durable worker identity is derived from GitHub's run id and run attempt.
No reusable runner credential is stored in the repository.

## Polling behavior

`.github/workflows/free-runner.yml` checks for pending work every five minutes.

The preflight does not check out the repository or install dependencies. It
only obtains an OIDC token and asks the Supabase runner gateway for one safe
job. Checkout, `npm ci`, builds and assessment execution happen only if a job
was actually leased.

GitHub scheduled workflows are not real-time queues and can start later than
their nominal cron interval during platform load.

## Dashboard use

1. Open the REAPER staging dashboard.
2. Authenticate with a REAPER API key.
3. In **Free staging assessment**, choose a project and enter an authorized
   HTTPS origin.
4. If the workspace has no project yet, the dashboard creates `Free Staging`.
5. Queue the assessment.
6. Refresh the run list after the GitHub runner processes it.

The API endpoint for the same operation is `POST /v1/free-runs`.

## Persistence

The runner gateway writes lifecycle events into the tamper-evident audit chain.
On successful completion it persists the full bounded report on the run and
normalizes valid findings into the control-plane findings table.

Unsafe jobs are never leased by the free-runner database function. Jobs asking
for mutation permissions or a different execution profile remain pending for a
different authorized execution plane.

## Cost boundary

This staging mode is designed to run without paid infrastructure while the
Supabase project remains within its Free-plan quotas and the public GitHub
repository remains eligible for GitHub-hosted Actions under GitHub's current
terms.

REAPER contains no automatic upgrade or paid-resource provisioning for the free
path. Platform quotas and provider terms can change, so this is not a guarantee
of permanent zero cost.

## Not a production security claim

The free runner is a laboratory/staging path. It intentionally does not claim
the same isolation or key-custody guarantees as the Cloud Run + Cloud KMS path.

For commercial active assessments, keep the hardened execution plane:
managed/dedicated runner isolation, real egress enforcement, signed scopes and
managed key custody.
