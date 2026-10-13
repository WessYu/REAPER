# Google Cloud managed execution

This module creates the Google-managed execution plane for REAPER:

```text
Cloud Scheduler
  -> dispatcher Cloud Run Job
     -> Cloud KMS Ed25519 signature
     -> runner Cloud Run Job execution with overrides
        -> strict REAPER engine
        -> PostgreSQL durable journal / replay / audit
```

The dispatcher and runner use separate service accounts and separate database
secrets. Terraform creates the Secret Manager containers but intentionally does
not create secret versions: database credentials must not be stored in Terraform
state.

## Required database logins

Create two PostgreSQL LOGIN roles outside Terraform and grant:

```sql
GRANT reaper_platform_dispatcher TO <dispatcher-login>;
GRANT reaper_platform_runner TO <runner-login>;
```

Store each connection URL as the latest version of the matching Secret Manager
secret output by this module.

## Network gate

`network_egress_enforced` defaults to `false`. With the default, the REAPER
runner advertises no network-isolation capability and strict mode fails closed.

Set it to `true` only after the Cloud Run runner's outbound path is constrained
by reviewed infrastructure. The application allowlist, DNS pinning and request
budgets remain defense in depth and are not a substitute for infrastructure
egress controls.

## Apply

```sh
terraform init
terraform plan \
  -var='project_id=YOUR_PROJECT_ID' \
  -var='runner_image=REGION-docker.pkg.dev/PROJECT/reaper/platform@sha256:...'

terraform apply
```

Use an immutable image digest, not `:latest`.

Cloud Run Jobs execute one task and set platform retries to zero. REAPER owns
retry decisions in the durable queue so a managed-platform retry cannot silently
duplicate a stateful assessment.
