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

## Independent authorization trust root

The Cloud Run **runner**, not the dispatcher, owns the trust registry used to
verify signed assessment scopes. The dispatcher can request a signature using
Cloud KMS, but **must never** include its fetched public key in the execution
envelope. The runner refuses any job that includes `trustedScopeKeys`,
`trustedKeys`, or `publicKey`.

Terraform creates `reaper-runner-trusted-scope-keys` in Secret Manager, grants
**only the runner service account** read access, and mounts the secret at the
fixed read-only volume path:

```text
/var/run/reaper-trust/trusted-scope-keys.json
```

The runner code reads this file directly. It does not accept a trust root from
job fields or a Cloud Run execution environment-variable override. The
dispatcher cannot replace this volume via the overrides used by
`CloudRunJobClient`.

An operator must independently retrieve the reviewed KMS public key, verify
its key version/fingerprint through the trusted cloud account, and populate a
secret version **before** enabling managed execution. Example file format:

```json
{
  "version": 1,
  "keys": [
    {
      "keyId": "gcp-kms-authorization-scope-v1",
      "issuer": "reaper-platform",
      "publicKeyPem": "-----BEGIN PUBLIC KEY-----\\nREPLACE_WITH_VERIFIED_KEY\\n-----END PUBLIC KEY-----\\n",
      "status": "active"
    }
  ]
}
```

The example is not a valid key. Use a real independently reviewed Ed25519
public key from the **exact** configured KMS key version. The trust registry
must not be generated from a signed job or its embedded metadata.

After provisioning the secret resource, a privileged operator can add the
reviewed local JSON without writing the key registry into Terraform state:

```sh
gcloud secrets versions add reaper-runner-trusted-scope-keys \\
  --project=YOUR_PROJECT_ID \\
  --data-file=./reviewed-trusted-scope-keys.json
```

This configuration is **integrity-sensitive**, although the verification keys
are public. Restrict write access to the secret and audit version changes.
The dispatcher service account must not have `secretAccessor` or write
permissions on this registry. The runner must not have KMS signing permission.

### Signing-key rotation

1. Create a new Ed25519 KMS key version and independently verify its public key.
2. Publish a new trusted registry secret version containing **both** the old
   and new keys. Give the old key status `retired` with an explicit
   `notAfter` overlap cutoff, and the new key status `active`.
3. Update Terraform `scope_signing_key_version` and
   `scope_signing_key_id` together. Key IDs are never reused.
4. Verify signed runs with the new key and that old scopes remain valid only
   during the declared overlap. After the cutoff, remove the old key.
5. For compromise, mark the old key `revoked` with `revokedAt` and publish
   the registry immediately; do not wait for the normal overlap.

Missing, invalid, expired, revoked, wrong-issuer or wrong-key trust entries
must fail closed **before** the runner makes a request. A Cloud Run job whose
secret version has not yet been populated cannot execute an assessment.

**Security boundary:** the runner-only secret volume prevents _job-envelope
self-attestation_. It is not a defense against a fully compromised cloud
administrator or an actor with arbitrary `run.jobsExecutorWithOverrides`
permissions, which can potentially change execution arguments. Minimize that
IAM grant and monitor job execution overrides. Do not claim full isolation
from a compromised dispatcher until the invocation authority is redesigned
and independently reviewed.

## Network gate

`network_egress_enforced` defaults to `false`. With the default, the REAPER
runner advertises no network-isolation capability and strict mode fails closed.

The Terraform module now creates an optional dedicated **Direct VPC egress**
network, /24 subnet, deny-all outbound firewall and two exact IPv4 /32
allowlists. A Cloud NAT instance is used for approved public IPv4 connections.
The runner receives the `reaper-execution` network tag and
`ALL_TRAFFIC` VPC routing. The dispatcher is **not** attached to this network.

Set `network_egress_enforced=true` only for a reviewed **single-customer pilot**.
Before applying, supply **all three**:

- `allowed_runner_target_cidrs`: one or more _verified and explicitly
  authorized_ target IPv4 addresses as /32s; only TCP 443 is allowed;
- `allowed_runner_database_cidrs`: independently reviewed, reachable
  PostgreSQL IPv4 address(es) as /32s; only TCP 5432 is allowed.

Each assessment hostname must resolve to its approved /32 address at execution
time; a change in DNS or an unavailable IPv4 transport should make the run
fail rather than widen the firewall. Use separate networks or separately
reviewed firewall updates for independent customer authorizations.
**Do not list 0.0.0.0/0, broad service-provider ranges or arbitrary
customer-owned networks** as a substitute for explicit targets.

When `network_egress_enforced=false`, the optional network and firewall
resources are not provisioned, the runner has no `vpc_access` attachment
and strict mode still fails closed. Terraform does not execute a packet-level
egress probe, test resource behavior, or prove that no organization-level
firewall policy overrides these resources. A successful `terraform validate`
alone is not production certification.

### Read-only deployed policy verification

After an authorized pilot apply, use a reviewer identity with Cloud Run Jobs
read and Compute Firewall read access:

```sh
export REAPER_GCP_PROJECT_ID="YOUR_PROJECT_ID"
export REAPER_GCP_REGION="southamerica-east1"
export GOOGLE_OAUTH_ACCESS_TOKEN="$(gcloud auth print-access-token)"
export REAPER_APPROVED_TARGET_CIDRS="APPROVED_IPV4/32"
export REAPER_APPROVED_DATABASE_CIDRS="APPROVED_DB_IPV4/32"
node scripts/verify-gcp-egress.mjs
```

The command reads **live** Cloud Run job templates and network firewall rules.
It fails if the network is missing, a shared service account is configured,
the deny rule is absent/disabled, a more-permissive rule defeats the deny,
or the observed destinations differ from the approved /32s. It emits
`CONFIGURATION_VERIFIED` only for configuration checks; **not** a claim of
packet-level network isolation. Test actual permitted and forbidden egress from
a disposable deployed runner and retain network-flow evidence before any
commercial execution. Always avoid printing the bearer token.

Network resources and especially Cloud NAT may incur **real cloud costs**.
Nothing in this repository change creates cloud resources until an operator
runs `terraform apply` with a configured GCP project and credentials.
The application allowlist, DNS pinning and request budgets remain defense in
depth and are not a substitute for these controls.

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
