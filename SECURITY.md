# Security policy

REAPER 0.1.x is experimental. Do not use a clean scan as authorization assurance.

Report a suspected vulnerability through GitHub private vulnerability reporting if enabled. Otherwise request a private contact channel in an issue without including secrets, customer data, targets or exploit details. Do not assume an issue is private.

## Execution boundaries

Source scanning reads files locally, never executes project code, and makes no network requests. Configuration is parsed as literal data. Dependency install/build are development operations, separate from scanning. Symlink entries and common generated directories are excluded.

Database introspection makes an explicit connection using an environment-provided credential, starts a read-only transaction and queries catalogs. REAPER does not request application rows or run project SQL. Use least-privilege credentials and appropriate TLS. Schema metadata remains sensitive.

Reports include paths, route names, role names and schema metadata. Store them with suitable access controls. File output is created with mode 0600 where supported; existing file permissions are not replaced. Baselines and suppressions are review decisions, not fixes.

Runtime HTTP verification is opt-in and assertion-driven. Localhost is allowed automatically; remote origins are blocked unless the exact origin is listed in `verify.allowedTargets`. Verification is limited to configured GET/HEAD requests, bounded concurrency, request budgets and per-request timeouts. Redirect following is disabled.

Authentication tokens are loaded from explicitly named environment variables and are not stored in configuration or copied into findings. REAPER does not discover credentials, brute-force accounts, enumerate the internet, submit destructive methods or create persistence. A CONFIRMED runtime finding means a configured security assertion observed an unexpected HTTP status; it does not by itself prove data exfiltration.

Only run verification against systems you own or are explicitly authorized to test. Use synthetic accounts/resources and a local or preview environment whenever possible.

The database integration tests deliberately mutate a disposable database. Their environment variable is separate from production DATABASE_URL. Never point REAPER_TEST_DATABASE_URL at a live application database.
