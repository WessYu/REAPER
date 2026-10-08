# Security policy

REAPER 0.2.x is experimental. Do not use a clean scan, a high score or a
successful runtime scenario as authorization assurance.

Report a suspected vulnerability through GitHub private vulnerability reporting
if enabled. Otherwise request a private contact channel in an issue without
including secrets, customer data, targets or exploit details. Do not assume an
issue is private.

## Execution boundaries

Source scanning reads files locally, never executes project code, and makes no
network requests. Configuration is parsed as literal data. Dependency
installation/build are development operations, separate from scanning. Symlink
entries and common generated directories are excluded.

Database introspection makes an explicit connection using an
environment-provided credential, starts a read-only transaction and queries
catalogs. REAPER does not request application rows, run migrations or invoke
application functions during catalog inspection. Use least-privilege credentials
and appropriate TLS. Schema metadata remains sensitive.

Reports include paths, route names, role names and schema metadata. Store them
with suitable access controls. File output is created with mode 0600 where
supported; existing file permissions are not replaced. Baselines and
suppressions are review decisions, not fixes.

## Runtime verification

Runtime verification is opt-in and authorization-scoped. Localhost is allowed
automatically. Remote origins are blocked unless the exact origin is listed in
`verify.allowedTargets`. Redirect following is disabled.

OpenAPI discovery checks only configured/default documentation paths and returns
GET/HEAD operations. Optional active probing is limited to non-templated
discovered GET/HEAD paths and inherits the same exact-origin authorization,
request budget, rate limit, timeout and cancellation controls. It does not crawl
arbitrary links or enumerate the public internet.

Assertions use GET/HEAD. Synthetic setup and teardown may use POST, PUT, PATCH
or DELETE only when the operator explicitly sets `verify.allowMutations: true`
and provides the exact paths and bodies. The optional `syntheticUsers`
provisioner is also mutation-gated and requires an explicit signup template,
token capture path and optional cleanup template; it never guesses account
creation, MFA/CAPTCHA behavior, destructive requests or credentials. Use
synthetic accounts/resources and local/preview environments whenever possible.

Runtime work is bounded by request budgets, rate limits, concurrency caps,
response-capture limits, timeouts and cancellation. Authentication tokens are
loaded from named environment variables or captured in memory from explicitly
configured setup responses. Token values are not copied into findings.

A CONFIRMED runtime finding means a configured security assertion observed an
unexpected HTTP status. It does not by itself prove data disclosure or general
exploitability.

Only run verification against systems you own or are explicitly authorized to
test.

## Local service

`reaper serve` binds to `127.0.0.1` only. It is intentionally a local review
service, not a hardened multi-user hosted API. Do not expose it through a public
reverse proxy without adding an appropriate authentication and isolation layer.

The database integration tests deliberately mutate a disposable database. Their
environment variable is separate from production `DATABASE_URL`. Never point
`REAPER_TEST_DATABASE_URL` at a live application database.
