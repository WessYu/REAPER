# REAPER staging

The first hosted REAPER Platform staging environment uses a dedicated Supabase project in `sa-east-1`.

## Hosted control plane

The staging dashboard and API are served by the Supabase Edge Function:

```text
https://szzdstxpdopprmgdjhcn.supabase.co/functions/v1/reaper-platform
```

The function uses the project-provided `SUPABASE_DB_URL` and a pinned `postgres` client. It implements REAPER API-key authentication itself, so the Supabase gateway JWT check is intentionally disabled for this function.

The API-key token format remains:

```text
reaper_live_<uuid>.<secret>
```

For this Edge staging adapter, the high-entropy token is stored as a SHA-256 digest. The original Node control plane continues to support HMAC-protected API-key digests through its runtime secret.

## Authorization boundary

The managed Edge database connection is privileged and cannot safely be treated as the dedicated `reaper_platform_api` login used by the Node runtime.

Therefore the Edge adapter does **not** claim PostgreSQL RLS is its primary isolation boundary. Instead it:

- authenticates through the internal `authenticate_api_key` function;
- binds every read to the authenticated `workspace_id`;
- writes the authenticated `workspace_id` on inserts;
- relies on composite workspace foreign keys for project/assessment/run consistency;
- uses the existing admin-checked functions for API-key creation and revocation;
- never exposes `SUPABASE_DB_URL` or Supabase secret keys to the browser.

The dedicated Node control plane and worker deployment model still uses restricted PostgreSQL runtime roles and RLS as defense in depth.

## Database migrations

Staging has applied:

1. `control-plane/001_init.sql`
2. `control-plane/002_platform.sql`
3. `control-plane/003_staging_hardening.sql`

Migration 003:

- fixes immutable function `search_path` configuration;
- makes the bootstrap policy planner-friendly;
- adds covering indexes for workspace foreign keys.

Supabase security advisors are clean after migration 003. Newly created indexes may appear as unused until staging carries real traffic.

## Runner boundary

The Edge Function is only the control plane. It does not execute active assessments.

A real active assessment still requires the dedicated worker/runner boundary from `platform/`:

```text
Control Plane
   |
PostgreSQL durable job
   |
Dedicated worker host
   |
External signer / KMS boundary
   |
Hardened ephemeral runner container
   |
Authorized target
```

Do not run the worker by mounting a host Docker socket into an untrusted web container.

## Current external gates

A complete production claim still requires evidence for:

- a dedicated Docker/VM worker host;
- enforced runner egress policy;
- external signing service backed by KMS/HSM;
- managed worker secret custody;
- centralized monitoring and alerts;
- backup/restore validation;
- independent penetration testing;
- deployment review and an authorized pilot.
