# Security policy

REAPER 0.1.x is experimental. Do not use a clean scan as authorization assurance.

Report a suspected vulnerability through GitHub private vulnerability reporting if enabled. Otherwise request a private contact channel in an issue without including secrets, customer data, targets or exploit details. Do not assume an issue is private.

## Execution boundaries

Source scanning reads files locally, never executes project code, and makes no network requests. Configuration is parsed as literal data. Dependency install/build are development operations, separate from scanning. Symlink entries and common generated directories are excluded.

Database introspection makes an explicit connection using an environment-provided credential, starts a read-only transaction and queries catalogs. REAPER does not request application rows or run project SQL. Use least-privilege credentials and appropriate TLS. Schema metadata remains sensitive.

Reports include paths, route names, role names and schema metadata. Store them with suitable access controls. File output is created with mode 0600 where supported; existing file permissions are not replaced. Baselines and suppressions are review decisions, not fixes.

Runtime HTTP verification is not implemented. No targets are probed. Future verification must implement explicit remote authorization, safe methods, budgets, rate/concurrency limits, cancellation and audit records before use.

The database integration tests deliberately mutate a disposable database. Their environment variable is separate from production DATABASE_URL. Never point REAPER_TEST_DATABASE_URL at a live application database.
