<p align="center">
  <img src="./assets/reaper-icon.svg" width="112" alt="REAPER icon" />
</p>

<h1 align="center">REAPER</h1>

<p align="center"><strong>Data Access Security Engine</strong></p>
<p align="center"><em>Know exactly who can access your data. Before an attacker does.</em></p>

[![CI](https://github.com/WessYu/REAPER/actions/workflows/ci.yml/badge.svg)](https://github.com/WessYu/REAPER/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/@wess2001/reaper.svg)](https://www.npmjs.com/package/@wess2001/reaper)

REAPER traces request input into supported database calls and reports authorization, tenant-isolation, SQL, migration, secret and database-posture risks. It can combine source analysis with read-only PostgreSQL evidence and can run explicitly configured, bounded authorization assertions against authorized targets.

The current `main` branch is **0.2.0 development**. The latest published npm release is **0.1.1**. Static/catalog findings identify patterns worth investigating, not proof that an application is exploitable. Runtime findings are only marked CONFIRMED when an explicitly configured authorization assertion observes a status different from its declared security expectation. A clean report does not establish security. There is no AI dependency, telemetry or automatic database repair.

## Install and run

Requires Node.js 22 or 24.

Run directly from npm:

```sh
npx @wess2001/reaper@0.1.1 --help
npx @wess2001/reaper@0.1.1 scan ./application
```

Or install the CLI globally:

```sh
npm install -g @wess2001/reaper@0.1.1
reaper --help
reaper scan ./application
```

For local development:

```sh
git clone https://github.com/WessYu/REAPER.git
cd REAPER
npm ci --ignore-scripts
npm run build
node dist/cli.js scan test/fixtures/vulnerable
node dist/cli.js scan test/fixtures/secure --fail-on medium
```

The vulnerable fixture produces one SQL, one ownership and one tenant finding. The secure fixture produces none of those findings. Both are analysis fixtures, not deployable applications.

## Implemented coverage

| Area            | Current behavior                                                                                                                                                          |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Parsing         | TypeScript compiler AST and symbol resolution for JS, TS, JSX and TSX                                                                                                     |
| Routes          | Express/Fastify registrations, supported sequential middleware and Next.js `route.ts` exported handlers                                                                   |
| Flow            | Assignments, destructuring, shared-object/property mutation, local imports, direct calls, `.call`/`.apply`, arrays, branches, bounded loops, try/catch/finally and switch |
| SQL             | Tainted SQL text in pg, Prisma unsafe raw calls and Knex raw; parsed constant UPDATE/DELETE without WHERE                                                                 |
| Data access     | Prisma authorization reasoning plus Supabase, Knex and Drizzle data-access discovery                                                                                      |
| PostgreSQL      | Read-only catalogs for tables, RLS, policies, inherited roles, table/schema/column grants, functions, views/materialized views and triggers                               |
| RLS             | Common policy-expression classification for identity, tenant, role-only and constant predicates; arbitrary SQL remains conservative                                       |
| Supabase        | Service-role exposure, table/RPC/Storage graph discovery, table/RPC/Storage source-to-catalog correlation                                                                 |
| Migrations      | SQL migration review for RLS removal, policy drops and broad grants                                                                                                       |
| Secrets/Crypto  | Embedded database credentials/private keys and fast password-hash misuse                                                                                                  |
| Verification    | Authorized assertions, bounded OpenAPI GET/HEAD discovery, optional synthetic setup/teardown, budgets, rate limits, timeouts and cancellation                             |
| Platform        | Self-contained HTML dashboard, localhost-only REST service and programmatic Rule SDK                                                                                      |
| Output          | Terminal, JSON, Markdown, SARIF 2.1.0, explanations, DOT/JSON graph and explainable security score                                                                        |
| Review workflow | Stable fingerprints, baselines, justified line suppressions and report diffs                                                                                              |

Local import resolution follows standard TypeScript module resolution within discovered files. The scanner does not load the target's compiler plugins, execute its configuration or import its dependencies.

## Authorization assumptions

A field named `userId` is not enough to infer an ownership relationship. REAPER uses a recognized Prisma `@relation(fields: [...])` to a conventional `User`/`Owner` or tenant model, or explicit configuration.

The default trusted principal paths are `req.user.id`, `request.user.id`, `req.auth.userId`, `request.auth.userId`, and the `tenantId`/`organizationId` properties of `req.user` and `request.user`. This is a **modeling assumption**: REAPER does not prove that authentication middleware established those values. Verify that assumption before relying on a scoped-query result.

Ownership and tenant findings are conservative. REAPER can model supported direct post-query deny guards and sequentially resolved Express/Fastify middleware that mutates the shared request object, but opaque framework wrappers, dynamically selected middleware and external authorization services still require review.

```ts
// reaper.config.ts — literal data only
export default {
  resources: {
    invoice: {
      ownership: ["userId"],
      tenant: ["organizationId"],
    },
  },
  principalPaths: ["req.user.id", "req.user.organizationId"],
  exclude: ["fixtures"],
  maxFiles: 10000,
  maxFileBytes: 1000000,
  verify: {
    allowedTargets: ["https://preview.example.com"],
    maxRequests: 20,
    concurrency: 2,
    timeoutMs: 5000,
    rateLimitPerSecond: 5,
    discoverOpenApi: true,
    openApiPaths: ["/openapi.json"],
    assertions: [
      {
        name: "cross-tenant order must be denied",
        path: "/api/orders/synthetic-tenant-b-order",
        expectStatus: 403,
        authEnv: "REAPER_TEST_USER_A_TOKEN",
        dimension: "tenant",
      },
    ],
  },
};
```

The CLI automatically reads this file at the scan root. `--config` selects another file. Calls, imports-as-values and executable expressions are rejected. `exclude` matches directory/file basenames, not glob patterns. The programmatic API accepts `config` or `configFile` explicitly.

## Commands

```sh
reaper scan ./application --format json --output scan.json
reaper sql ./application
reaper authz ./application
reaper tenants ./application
reaper supabase ./application
reaper migrations ./application
reaper crypto ./application
reaper scan ./application --db-env DATABASE_URL --format json --output combined.json
reaper graph combined.json --format dot --output graph.dot
reaper score combined.json
reaper discover http://localhost:3000 --config reaper.config.ts
reaper verify http://localhost:3000 --config reaper.config.ts --fail-on high
reaper dashboard combined.json --output reaper-dashboard.html
reaper serve ./application --port 7337
reaper baseline scan.json --output baseline.json
reaper scan ./application --baseline baseline.json --fail-on high
reaper report scan.json --format sarif --output reaper.sarif
reaper report scan.json --format markdown --output review.md
reaper diff previous.json scan.json
reaper explain REAPER-SQL-001:0123456789ab --input scan.json
reaper doctor
```

Use an actual finding ID from your report with `explain`. `diff` compares saved findings, not SQL migrations or Git trees. Baselines only acknowledge exact fingerprints; findings remain in the report. Fingerprints are stable across blank-line changes but may change after query, route or path edits. Identical queries in the same file and route currently share an identity.

Exit codes: **0** completed without a failed gate; **1** new findings meet `--fail-on`; **2** invalid input, operational error or reported incomplete analysis. A completed scan still has the coverage limits below.

Suppression applies to the immediately following finding line and requires a specific rule and a reason of at least ten characters:

```ts
// reaper-ignore REAPER-AUTH-001 -- reason: ownership is enforced by the reviewed object guard
return prisma.order.findUnique({ where: { id: req.params.id } });
```

## PostgreSQL

Set `DATABASE_URL` through your shell or secret manager. It is never accepted as a CLI flag value or stored by REAPER.

```sh
reaper schema --db-env DATABASE_URL --output catalog.json
reaper rls --db-env DATABASE_URL --format json --output rls.json
reaper privileges --db-env DATABASE_URL
```

Inspection uses a repeatable-read, read-only transaction with connection, query, statement and lock timeouts. It reads system catalogs; it does not fetch application rows, execute migrations or invoke application functions. TLS follows the pg connection settings; certificate checks are not disabled.

Passing `--db-env` to a source command explicitly combines source findings with a database snapshot. Supported Supabase table, RPC and Storage paths can be correlated with PostgreSQL grants, RLS policies and SECURITY DEFINER posture. This raises confidence because both source and catalog evidence were observed, but it still does not prove internet exposure or exploitability.

A broad table grant plus missing RLS is a review candidate, not proof of public API exposure. RLS with no policies is default-deny information. REAPER classifies common `auth.uid()`, JWT tenant, role-only and constant policy predicates, while arbitrary SQL predicates remain conservative. Role membership with ROLINHERIT is expanded for effective grants. Broad schema CREATE, BYPASSRLS/SUPERUSER roles, client-readable owner-rights views, privilege-sensitive triggers and broadly executable SECURITY DEFINER functions with unsafe `search_path` are reviewed.

Only connect to databases you are authorized to inspect. Start with a dedicated low-privilege role. Catalog snapshots reveal schema and role names; handle reports as internal security material.

## Authorized runtime verification

`reaper verify` remains authorization-scoped rather than an open-ended web scanner. Localhost targets are permitted automatically. Remote origins are blocked unless their exact origin is listed in `verify.allowedTargets`.

REAPER can optionally discover GET/HEAD operations from an allowlisted target's OpenAPI document. Assertions remain operator-defined. Synthetic scenario setup/teardown can use POST, PUT, PATCH or DELETE only when `verify.allowMutations: true` is explicitly configured. Setup responses can capture bounded JSON values such as synthetic IDs or tokens into in-memory variables for later assertions and cleanup. Token values are not copied into findings.

Redirect following is disabled. Concurrency, request rate, total request budget, response-capture size and per-request timeout are bounded, and Ctrl+C cancellation is propagated through the scenario. A runtime finding means a security property that **you explicitly declared** did not produce the expected HTTP status. REAPER does not brute-force credentials, crawl arbitrary internet targets or invent destructive requests.

## TypeScript API

```ts
import { scan, report } from "@wess2001/reaper";

const result = await scan({
  root: process.cwd(),
  rules: [
    {
      id: "REAPER-CUSTOM-001",
      run(context) {
        // Programmatic custom rules can inspect the normalized report/graph
        // and emit deterministic findings through context.add(...).
      },
    },
  ],
});

console.log(report(result, "json"));
```

## Architecture

`project.ts` bounds file discovery and extracts basic Prisma relationships. `analysis.ts` uses the compiler's symbols and a bounded abstract interpreter to propagate input provenance into database sinks. `sql.ts` parses constant SQL. `postgres.ts` collects and reviews catalog evidence. `model.ts`, `findings.ts` and `reporter.ts` define the public result contract, fingerprints and output formats. `cli.ts` orchestrates those modules.

The graph represents observed route → query → resource edges. It is not yet a complete authorization or privilege graph. Source text and credentials are not copied into findings; flow evidence contains labels and locations.

## Validation and CI

```sh
npm run check
npm pack
# A disposable database is required for this separate integration suite:
node --test test/integration/postgres.mjs
```

For the integration command, set `REAPER_TEST_DATABASE_URL` to a disposable PostgreSQL database. **The test harness creates and drops synthetic tables and a test role**; production introspection does not. GitHub Actions runs Node 22/24, PostgreSQL 17 integration, lint, formatting, strict typechecking, unit/CLI tests and installation from the packed tarball.

SARIF can be uploaded with GitHub's Code Scanning action in a consuming repository. Review repository access and report sensitivity before uploading. REAPER itself does not upload reports.

## Known limits and next work

- Control-flow and alias analysis are **bounded abstract interpretation**, not a proof-complete JavaScript execution model. Loops are analyzed conservatively without arbitrary fixed-point iteration, recursion is bounded, and async/event context is not fully reconstructed.
- Shared-object property mutation, direct function calls, `.call`/`.apply`, supported middleware chains, try/catch/finally and switch are modeled, but proxies, reflection, runtime code generation, arbitrary decorators, opaque framework wrappers and highly dynamic dispatch can remain unresolved.
- Next.js support is centered on exported route handlers. Middleware analysis currently requires resolvable functions in supported route registrations; externally configured or dynamically selected middleware still requires review.
- RLS reasoning recognizes common identity, tenant, role-only and constant patterns. It does not theorem-prove arbitrary SQL functions, subqueries or all combinations of permissive/restrictive policies.
- PostgreSQL view and trigger posture is inspected, but full dependency-level privilege composition, trigger-body semantics and extension-specific authorization models remain conservative. Column grants are collected but are not yet fully correlated with selected fields.
- Prisma has the deepest authorization semantics. Drizzle and Knex are represented in the data-access graph, but their ownership/tenant reasoning is not yet as rich as Prisma's.
- OpenAPI discovery is intentionally limited to GET/HEAD operations from configured documentation endpoints. Synthetic account/resource creation is configuration-driven; REAPER does not guess signup flows, MFA/CAPTCHA handling or cleanup semantics.
- The localhost REST service is intentionally small and unauthenticated because it binds only to `127.0.0.1`; it is not a hosted multi-user service.
- The numerical score is a triage aid. A clean scan or a high score is not authorization assurance.

The next work should focus on precision, framework-specific authorization adapters and deeper data-layer correlation rather than adding unsupported breadth. See [rules](docs/rules.md), [security policy](SECURITY.md) and [contributing](CONTRIBUTING.md).
