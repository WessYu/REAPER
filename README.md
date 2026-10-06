<p align="center">
  <img src="./assets/reaper-icon.png" width="180" alt="REAPER icon" />
</p>

<h1 align="center">REAPER</h1>

<p align="center"><strong>Data Access Security Engine</strong></p>
<p align="center"><em>Know exactly who can access your data. Before an attacker does.</em></p>

[![CI](https://github.com/WessYu/REAPER/actions/workflows/ci.yml/badge.svg)](https://github.com/WessYu/REAPER/actions/workflows/ci.yml)

REAPER traces request input into supported database calls and reports queries whose ownership or tenant constraints cannot be established. It also inspects PostgreSQL catalogs for selected RLS and privilege risks.

Version **0.1.0 is experimental**. Findings identify patterns worth investigating, not proof that an application is exploitable. A clean report does not establish security. There is no AI dependency, telemetry, active HTTP scanner or automatic database repair.

## Run locally

Requires Node.js 22 or 24.

```sh
git clone https://github.com/WessYu/REAPER.git
cd REAPER
npm ci --ignore-scripts
npm run build
node dist/cli.js scan test/fixtures/vulnerable
node dist/cli.js scan test/fixtures/secure --fail-on medium
```

The vulnerable fixture produces one SQL, one ownership and one tenant finding. The secure fixture produces none of those findings. Both are analysis fixtures, not deployable applications.

To install the built CLI from a local tarball:

```sh
npm pack
npm install -g ./wess2001-reaper-0.1.0.tgz
reaper --help
```

The npm package has **not** been published. Do not assume `npx @wess2001/reaper` is available.

## Implemented coverage

| Area            | Current behavior                                                                                                                 |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Parsing         | TypeScript compiler AST and symbol resolution for JS, TS, JSX and TSX                                                            |
| Routes          | Express/Fastify method registration with imported factory provenance; Next.js `route.ts` exported function handlers              |
| Flow            | Assignments, destructuring, local imports, direct calls, string interpolation, early returns and conservative `if` branch merges |
| SQL             | Tainted text passed to pg, Prisma unsafe raw calls and Knex raw; parsed constant UPDATE/DELETE without WHERE                     |
| Prisma          | Query filters checked against declared or inferred resource relationships                                                        |
| PostgreSQL      | Read-only catalog snapshot: tables, RLS state, policies, roles and table grants                                                  |
| Output          | Terminal, JSON, Markdown, SARIF 2.1.0, finding explanation and route/query/resource graph in JSON                                |
| Review workflow | Stable fingerprints, baselines, justified line suppressions and report diffs                                                     |

Local import resolution follows standard TypeScript module resolution within discovered files. The scanner does not load the target's compiler plugins, execute its configuration or import its dependencies.

## Authorization assumptions

A field named `userId` is not enough to infer an ownership relationship. REAPER uses a recognized Prisma `@relation(fields: [...])` to a conventional `User`/`Owner` or tenant model, or explicit configuration.

The default trusted principal paths are `req.user.id`, `request.user.id`, `req.auth.userId`, `request.auth.userId`, and the `tenantId`/`organizationId` properties of `req.user` and `request.user`. This is a **modeling assumption**: REAPER does not prove that authentication middleware established those values. Verify that assumption before relying on a scoped-query result.

Ownership and tenant findings have MEDIUM confidence. Authorization performed by middleware, post-query guards, a separate service or database RLS may make a flagged query safe. Review the path before treating it as a vulnerability.

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

A broad table grant plus missing RLS is a review candidate, not proof of public API exposure. RLS with no policies is default-deny information. Constant TRUE in a permissive policy is reported at MEDIUM severity because restrictive policies and privileges can narrow effective access. Role inheritance and effective policy composition are not solved.

Only connect to databases you are authorized to inspect. Start with a dedicated low-privilege role. Catalog snapshots reveal schema and role names; handle reports as internal security material.

## TypeScript API

```ts
import { scan, report } from "@wess2001/reaper";

const result = await scan({ root: process.cwd() });
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

- No complete CFG, points-to analysis, async context modeling or incremental cache. Direct-call expansion is bounded and recursion is reported as incomplete.
- Loops, try/catch and switch are reported as unsupported. Generic middleware, framework wrappers, CommonJS imports, tsconfig path aliases and dynamic imports are not resolved reliably.
- Next.js support is limited to exported function handlers. Direct post-query ownership/tenant deny-guards using trusted principal paths and a terminating `throw` are modeled; generic authentication adapters, middleware proofs and complex guard semantics are not.
- Unknown helper calls preserve taint but are not certified sanitizers. Escaping, numeric conversion and allowlists may require review rather than removing a finding.
- Prisma schema inference supports a conventional relation subset; explicit configuration is needed for custom schemas. `sensitive` metadata is reserved and does not affect severity yet.
- Supabase JS coverage currently detects service-role exposure in hardcoded/client-public configuration and records table/RPC calls in the data graph. RLS/RPC catalog correlation and storage policies are not yet modeled. Drizzle, password/crypto checks, migrations, inherited grants, functions, views and column privileges are also not covered yet.
- No active `verify`, REST service, dashboard, rule SDK or numerical security score. Unimplemented commands fail explicitly.

The next priority is deeper authorization/RLS correlation and additional data-access adapters while preserving conservative findings and false-positive tests. See [rules](docs/rules.md), [security policy](SECURITY.md) and [contributing](CONTRIBUTING.md).
