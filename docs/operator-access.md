# Platform operator access and evidence export

This guide describes currently implemented staging and local-platform behavior. It does not claim that REAPER has production-grade end-user identity, SSO, MFA or billing.

## Authenticate

- Bootstrap an organization/workspace using the documented platform bootstrap path or obtain a scoped REAPER API key from an authorized workspace administrator.
- Open the hosted staging dashboard described in [staging.md](./staging.md), or the loopback-only Node dashboard started through `npm run platform:serve`.
- Paste the API key into the password input and choose **Connect**. The dashboard keeps the token only in page memory; it does not persist it in browser storage. Reloading or disconnecting requires re-entering the key.
- Use **Disconnect** before leaving a shared device. Revocation, expiration and role enforcement remain server-side.

Do not copy keys into issue comments, GitHub Actions logs or report files. Prefer short-lived, least-privilege API keys for individual operators. API keys are not a replacement for an identity provider, per-user audit trails, MFA and session management in a public SaaS deployment.

## API key rotation

Newly issued API keys expire after **30 days** unless the administrator
requests a shorter date, with an absolute **90-day maximum**. A request with
`expiresAt: null` no longer creates a permanent key. Existing keys, including
the initial bootstrap credential, keep their original expiry until explicitly
rotated or revoked. This change does **not** silently revoke existing keys.

For the staging workspace, create a replacement admin key while the bootstrap
credential remains valid, store the new token securely, confirm a successful
authenticated request, and only then revoke the old credential. A zero-expiry
bootstrap key is a tracked release risk until rotated. If every admin
credential expires, recovery requires a separately reviewed administrative
database bootstrap/recovery procedure; do not bypass authentication on the API.

## Projects and workspaces

All `/v1` requests require the `Authorization: Bearer` header. Projects, assessments, runs, findings, audit events and API keys are scoped by the authenticated workspace. Viewer roles cannot create new projects or runs; admin role is needed to issue or revoke API keys. Node database access additionally uses workspace RLS; privileged Supabase Edge calls must filter explicitly by workspace.

The staging dashboard allows authorized read-only assessment queuing with a fixed safety profile. See [free-staging.md](./free-staging.md).

## Export completed reports

After a run reaches `COMPLETED`, choose **Export JSON** in the run list. The dashboard fetches the run through the authenticated `GET /v1/runs/:id` endpoint and downloads only the selected run's ID, target, environment, status and recorded report. A non-completed run has no export action.

Exports are operational evidence, not a guarantee of security. Store downloaded reports in a controlled location, restrict sharing and respect retention requirements. The browser never fetches target URLs directly.

## Boundaries remaining for a commercial launch

- An external user identity provider, MFA/SSO, organization provisioning, invitations and account recovery are **not implemented**.
- Billing, subscription entitlements, quotas and retention policies are **not implemented**.
- Production isolation, egress enforcement, managed KMS, alerting, restore drills and independent security review still require operator-controlled cloud resources and real validation.
- The free runner is an intentionally restricted staging demonstration, not a substitute for the isolated commercial execution plane.

A successful CI suite or healthy staging database alone is not permission to market REAPER as a full autonomous pentest service.
