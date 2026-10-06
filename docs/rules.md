# Implemented rules

Most 0.1.0 findings are static/catalog observations. `REAPER-VERIFY-001` uses CONFIRMED confidence only when an explicitly configured runtime authorization assertion receives an unexpected HTTP status.

| Rule              | Evidence                                                                                    | Severity / confidence | Important boundary                                                            |
| ----------------- | ------------------------------------------------------------------------------------------- | --------------------- | ----------------------------------------------------------------------------- |
| REAPER-SQL-001    | HTTP input flows into a supported SQL text argument                                         | HIGH / HIGH           | Bound value arrays and Prisma tagged templates are not SQL text interpolation |
| REAPER-SQL-002    | Parsed constant UPDATE/DELETE has no WHERE                                                  | MEDIUM / HIGH         | Whole-table maintenance can be intentional                                    |
| REAPER-AUTH-001   | Request-dependent Prisma filter on a related resource has no supported principal constraint | MEDIUM / MEDIUM       | Middleware and post-query guards may authorize access                         |
| REAPER-TENANT-001 | Route reaches a related tenant resource without supported tenant constraint                 | MEDIUM / MEDIUM       | Source analysis does not prove database RLS                                   |
| REAPER-RLS-001    | PUBLIC/anon/authenticated table grant and RLS disabled                                      | HIGH / MEDIUM         | Schema exposure and application paths need independent verification           |
| REAPER-RLS-002    | RLS enabled and no policies                                                                 | INFO / MEDIUM         | Default deny, not default allow; bypass roles remain relevant                 |
| REAPER-RLS-003    | Broad-role permissive policy has constant TRUE USING or CHECK                               | MEDIUM / MEDIUM       | Restrictive policies, commands and grants affect effective access             |
| REAPER-PRIV-001   | Broad role has TRUNCATE, TRIGGER or REFERENCES                                              | HIGH / MEDIUM         | Review intended privilege; owner privileges alone are not flagged             |

Source analysis recognizes direct post-query ownership or tenant comparisons against trusted principal paths when the denial branch terminates with `throw`, including results returned through supported direct helper calls. It does not treat request-supplied identities, non-terminating comparisons, arbitrary middleware or opaque helper functions as authorization proof.

### REAPER-SUPA-001

Reports a HIGH/HIGH finding when REAPER can establish that a Supabase service-role
credential is hardcoded, or is referenced from client-exposed configuration.
JWT payloads are inspected only to identify the `service_role` claim; the raw
credential is not stored in the finding. Public anon/publishable key references
are not findings by themselves.

Supabase table operations and RPC calls are also represented as data-access
graph sinks.

### REAPER-SUPA-002

When a source scan is combined with `--db-env`, REAPER correlates supported
Supabase table operations with the PostgreSQL snapshot. A HIGH/HIGH finding is
created only when the same table is observed in source, the required operation
is effectively granted to a broad client role (including inherited grants) and
RLS is disabled.

This is stronger evidence than either observation alone, but it still does not
prove that a public HTTP path exposes the table.

### REAPER-SUPA-003

When a supported Supabase `rpc()` call is combined with a PostgreSQL snapshot,
REAPER correlates the RPC name with functions in the `public` schema.
A HIGH/HIGH finding requires all of the following: the function is
`SECURITY DEFINER`, a broad client role has effective `EXECUTE`, and the
function-local `search_path` is missing or contains an untrusted schema such
as `public`, `pg_temp` or `$user`.

### Runtime verification

`REAPER-VERIFY-001` is HIGH/CONFIRMED for configured ownership/anonymous
assertions and CRITICAL/CONFIRMED for configured tenant-isolation assertions
when the observed status differs from the expected status. REAPER does not
invent the expectation: the operator supplies the exact path, expected status
and optional token environment variable.

Role membership is expanded through PostgreSQL memberships when ROLINHERIT applies. Source and catalog results are still not combined into an exploitability proof. No score is computed because coverage is too incomplete to justify one.

### PostgreSQL privilege graph and SECURITY DEFINER

REAPER expands PostgreSQL role memberships for roles that inherit privileges.
This lets table/schema grants assigned to an intermediate role contribute to the
effective access of `anon`, `authenticated` or other broad roles.

- `REAPER-PRIV-002` reports broad effective `CREATE` on application schemas.
- `REAPER-PRIV-003` reports broad roles with SUPERUSER or BYPASSRLS.
- `REAPER-PG-001` reports broadly executable `SECURITY DEFINER` functions
  when no function-local `search_path` is set or it contains `$user`,
  `public` or `pg_temp`.

These remain review findings. REAPER does not claim a privilege-escalation path
unless it can establish the relevant grants and unsafe function posture.
