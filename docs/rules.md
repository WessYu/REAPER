# Implemented rules

REAPER 0.2.0 combines static source observations, PostgreSQL catalog posture and
explicit runtime assertions. Static/catalog findings are review evidence.
`REAPER-VERIFY-001` uses CONFIRMED confidence only when a configured runtime
security expectation receives an unexpected HTTP status.

## Source and authorization

| Rule              | Evidence                                                                                      | Severity / confidence                                 | Boundary                                                                      |
| ----------------- | --------------------------------------------------------------------------------------------- | ----------------------------------------------------- | ----------------------------------------------------------------------------- |
| REAPER-SQL-001    | HTTP-controlled data reaches a supported raw SQL text argument                                | HIGH / HIGH                                           | Bound value arrays and tagged parameterization are not SQL text interpolation |
| REAPER-SQL-002    | Parsed constant UPDATE/DELETE has no WHERE                                                    | MEDIUM / HIGH                                         | Whole-table maintenance can be intentional                                    |
| REAPER-AUTH-001   | Request-dependent Prisma access lacks a supported ownership constraint                        | MEDIUM / MEDIUM, raised for configured sensitive data | Middleware, post-query guards or DB policy may still authorize                |
| REAPER-TENANT-001 | Route reaches a tenant-scoped Prisma resource without a supported tenant constraint           | MEDIUM / MEDIUM, raised for configured sensitive data | Database RLS is independent evidence                                          |
| REAPER-SUPA-001   | Supabase service-role credential is hardcoded or referenced from client-exposed configuration | HIGH / HIGH                                           | Public anon/publishable keys are not findings by themselves                   |

Source analysis recognizes supported direct post-query ownership/tenant deny
guards, direct helper returns and sequentially resolved Express/Fastify route
middleware that mutates the shared request object. Opaque middleware can be
modeled through literal `middleware.<name>.establishes` contracts when the
operator explicitly declares which trusted request principal it establishes.
Request-supplied identities, non-terminating comparisons and unconfigured
dynamic middleware are not treated as authorization proof.

## PostgreSQL, RLS and privilege posture

| Rule               | Evidence                                                                                 | Severity / confidence |
| ------------------ | ---------------------------------------------------------------------------------------- | --------------------- |
| REAPER-RLS-001     | Broad table grant with RLS disabled                                                      | HIGH / MEDIUM         |
| REAPER-RLS-002     | RLS enabled with no policies                                                             | INFO / MEDIUM         |
| REAPER-RLS-003     | Broad permissive policy has constant TRUE USING/CHECK                                    | MEDIUM / MEDIUM       |
| REAPER-RLS-004     | Broad permissive policy is recognized as role-only without row identity                  | MEDIUM / MEDIUM       |
| REAPER-RLS-005     | Scoped permissive policy coexists with an unscoped permissive alternative                | MEDIUM / MEDIUM       |
| REAPER-PRIV-001    | Broad role has TRUNCATE, TRIGGER or REFERENCES                                           | HIGH / MEDIUM         |
| REAPER-PRIV-002    | Broad role has effective CREATE on an application schema                                 | HIGH / MEDIUM         |
| REAPER-PRIV-003    | Broad application role is SUPERUSER or BYPASSRLS                                         | CRITICAL / MEDIUM     |
| REAPER-PG-001      | Broadly executable SECURITY DEFINER function has unsafe function-local search_path       | HIGH / MEDIUM         |
| REAPER-PG-002      | Broadly executable SECURITY DEFINER function contains dynamic-SQL construction/execution | MEDIUM / MEDIUM       |
| REAPER-VIEW-001    | Broadly readable view does not use security_invoker                                      | HIGH / MEDIUM         |
| REAPER-TRIGGER-001 | Broad table DML can invoke a SECURITY DEFINER trigger function with unsafe search_path   | HIGH / MEDIUM         |

Role membership is expanded through PostgreSQL memberships when ROLINHERIT
applies. RLS expressions are classified for common identity
(`auth.uid()`), tenant/JWT, role-only and constant predicates. Bounded boolean
composition requires every OR branch to preserve a claimed isolation property,
while a constraining AND conjunct can establish it. PostgreSQL permissive
policies are treated as OR alternatives and restrictive policies as additional
constraints. REAPER still does not theorem-prove arbitrary SQL functions,
subqueries or procedural policy helpers.

View findings include catalog-derived relation dependencies and call out
RLS-protected relations reached through owner-rights view semantics. Trigger
findings correlate the table grant, trigger function and
SECURITY DEFINER/search_path posture. SECURITY DEFINER definitions are also
reviewed for dynamic-SQL primitives. Full trigger/function semantic execution
remains a review boundary.

## Supabase source-to-database correlation

### REAPER-SUPA-002

When a source scan is combined with `--db-env`, REAPER correlates a supported
Supabase table operation with the same PostgreSQL table. A HIGH/HIGH finding
requires the operation to be effectively granted to a broad client role while
RLS is disabled.

### REAPER-SUPA-003

A supported Supabase `rpc()` call is correlated with functions in the
`public` schema. A HIGH/HIGH finding requires a SECURITY DEFINER function,
effective broad EXECUTE and an unsafe/missing function-local `search_path`.

### Supabase Storage

| Rule               | Evidence                                                                                          | Severity / confidence |
| ------------------ | ------------------------------------------------------------------------------------------------- | --------------------- |
| REAPER-STORAGE-001 | `storage.objects` exists with RLS disabled                                                        | HIGH / MEDIUM         |
| REAPER-STORAGE-002 | Broad permissive `storage.objects` policy has a constant-open predicate                           | HIGH / MEDIUM         |
| REAPER-STORAGE-003 | Observed Supabase Storage source path reaches broadly granted `storage.objects` with RLS disabled | HIGH / HIGH           |
| REAPER-STORAGE-004 | Observed Supabase Storage source path is covered by a broad constant-open policy                  | HIGH / HIGH           |

Storage source graph support recognizes bucket-scoped operations such as
download, upload, update, remove, list, move, copy and signed-URL creation.
Storage policy correlation currently reasons at the `storage.objects` policy
level; it does not fully solve arbitrary bucket/path expressions.

## Migrations

| Rule                 | Evidence                                             | Severity / confidence |
| -------------------- | ---------------------------------------------------- | --------------------- |
| REAPER-MIGRATION-001 | Migration disables RLS                               | HIGH / HIGH           |
| REAPER-MIGRATION-002 | Migration removes FORCE ROW LEVEL SECURITY           | MEDIUM / HIGH         |
| REAPER-MIGRATION-003 | Migration drops an RLS policy                        | MEDIUM / HIGH         |
| REAPER-MIGRATION-004 | Migration grants broad/dangerous database privileges | MEDIUM or HIGH / HIGH |

Migration analysis is statement-oriented. It does not reconstruct a complete
before/after schema across every ORM migration representation.

## Secrets and password crypto

| Rule              | Evidence                                                    | Severity / confidence |
| ----------------- | ----------------------------------------------------------- | --------------------- |
| REAPER-CRYPTO-001 | Database URL with embedded credentials in source            | HIGH / HIGH           |
| REAPER-CRYPTO-002 | Private-key PEM material embedded in source                 | CRITICAL / HIGH       |
| REAPER-CRYPTO-003 | Fast general-purpose hash is applied to password-like input | MEDIUM or HIGH / HIGH |

Credential/key values are intentionally omitted from findings.

## Runtime verification

`REAPER-VERIFY-001` is HIGH/CONFIRMED for configured
ownership/anonymous assertions and CRITICAL/CONFIRMED for configured
tenant-isolation assertions when the observed status differs from the expected
status.

REAPER does not invent the security expectation. The operator supplies the
assertion. Optional setup/teardown requests are explicitly configured and
require `allowMutations: true`. Captured IDs/tokens stay in memory and can be
used by later assertions/cleanup without copying token values into findings.

OpenAPI discovery is limited to GET/HEAD operations from configured/default
documentation paths on localhost or an exact allowlisted origin. Optional active
probing reuses the same budgets, rate limits, timeout, cancellation and target
authorization and skips templated paths.

The `syntheticUsers` scenario can create two to four synthetic principals from
an explicitly configured POST/PUT template, capture token/ID JSON paths into
in-memory variables, use those identities in authorization assertions, and
invoke an explicitly configured DELETE cleanup path. REAPER never guesses the
signup flow or credentials.

## Active security findings

Active-security findings use CONFIRMED confidence only when an explicitly configured stateful scenario observes a result outside the declared security expectation. The engine does not infer exploitability from status codes alone unless the scenario declares the intended denial or invariant.

| Rule              | Confirmed evidence                                                    | Severity / confidence |
| ----------------- | --------------------------------------------------------------------- | --------------------- |
| REAPER-ATTACK-001 | Cross-user object/BOLA scenario receives a non-denied result          | HIGH / CONFIRMED      |
| REAPER-ATTACK-002 | Cross-tenant scenario violates the declared tenant boundary           | CRITICAL / CONFIRMED  |
| REAPER-ATTACK-003 | Lower-privilege identity violates an explicit privilege boundary      | CRITICAL / CONFIRMED  |
| REAPER-ATTACK-004 | Generic authorization scenario violates its configured expectation    | HIGH / CONFIRMED      |
| REAPER-ATTACK-005 | Session scenario violates the configured session expectation          | HIGH / CONFIRMED      |
| REAPER-ATTACK-006 | CORS scenario violates configured status/header expectations          | HIGH / CONFIRMED      |
| REAPER-ATTACK-007 | CSRF scenario violates its explicitly configured security expectation | HIGH / CONFIRMED      |
| REAPER-ATTACK-008 | Business-security scenario violates status/header/JSON invariants     | HIGH / CONFIRMED      |

A source/database report can be supplied to active mode. Matching authorization, tenant, RLS, privilege or Supabase evidence is attached to the active path without converting unrelated static observations into confirmed vulnerabilities. The combined graph preserves the source route → query → resource evidence and adds principal/request/runtime correlation.

Active scenario execution is target- and path-scoped, mutation-gated and bounded by request, mutation, rate, timeout and server-error budgets. Production requires additional authorization metadata and separate mutation consent. Tokens, cookies and captured response bodies are omitted from findings and audit records.

OpenAPI and GraphQL planning commands are passive: they model supplied schemas/introspection and do not send mutation/fuzzing traffic. The loopback callback collector is local/CI-only and is not a public OAST service.

## Rule SDK

The programmatic API can pass `rules` to `scan()`. A custom rule receives a
normalized `ScanResult`, validated config and a deterministic `context.add()`
finding helper. Custom rule IDs must use the `REAPER-...` namespace and are
checked for duplicates.

Custom rules run inside the caller's Node.js process. They are code supplied by
the API consumer, unlike `reaper.config.ts`, which remains literal data and is
never executed.

## Score boundary

The numerical score is an explainable triage aid. Severity and confidence
produce category penalties, and critical/high findings cap the overall score.
It does not convert incomplete analysis into proof that an application is
secure.
