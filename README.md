<p align="center">
  <img src="assets/reaper-icon.webp" alt="REAPER" width="104" />
</p>

<h1 align="center">REAPER</h1>
<p align="center"><strong>Data Access Security Engine</strong></p>
<p align="center">Trace how requests reach data. Review authorization, tenancy, SQL, and database exposure before release.</p>

<p align="center">
  <a href="https://github.com/WessYu/REAPER/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/WessYu/REAPER/actions/workflows/ci.yml/badge.svg" /></a>
  <a href="https://www.npmjs.com/package/@wess2001/reaper"><img alt="npm version" src="https://img.shields.io/npm/v/@wess2001/reaper.svg" /></a>
  <a href="LICENSE"><img alt="MIT license" src="https://img.shields.io/badge/license-MIT-111111.svg" /></a>
</p>

<p align="center">
  <img src="assets/reaper-banner.svg" alt="REAPER — Data Access Security Engine" width="100%" />
</p>

REAPER is a deterministic security analyzer for JavaScript/TypeScript applications and PostgreSQL. It combines source-level data-flow analysis with optional **read-only database catalog inspection** and **explicitly authorized, bounded runtime checks**.

Its findings are evidence for investigation—not an exploitability guarantee, formal proof of authorization, or substitute for a manual security review.

## Get started

**Requirements:** Node.js 22 or 24.

Use the published CLI:

```sh
npx @wess2001/reaper@0.2.0 --help
npx @wess2001/reaper@0.2.0 scan ./your-app
```

Or install it globally:

```sh
npm install -g @wess2001/reaper@0.2.0
reaper scan ./your-app --format json --output reaper.json
```

**Release boundary:** `0.2.0` is published on npm. The `main` branch is under active development; changes merged after the npm publication may only be available from source until a new package is released. Use `reaper --help` to check which commands your installed package provides.

To run the current repository code:

```sh
git clone https://github.com/WessYu/REAPER.git
cd REAPER
npm ci --ignore-scripts
npm run build
node dist/cli.js scan test/fixtures/vulnerable
node dist/cli.js scan test/fixtures/secure --fail-on medium
```

The vulnerable fixture contains known SQL, ownership and tenant-isolation mistakes; the secure control fixture is expected to produce no findings from those rule families. Both are **synthetic source fixtures**, not running targets.

## What it checks

| Area | Implemented behavior |
| --- | --- |
| **Application code** | TypeScript AST/symbol-based tracing across supported Express, Fastify and Next.js handlers, imports, assignments and control flow |
| **Data access** | Review of ownership and tenant constraints in supported Prisma patterns, with Drizzle, Knex and Supabase data-access discovery |
| **SQL and migrations** | Unsafe raw query construction, selected unscoped write queries, RLS changes, broad grants and migration risks |
| **PostgreSQL** | Read-only inspection of tables, grants, role inheritance, RLS policies, views, functions and triggers |
| **Secrets and cryptography** | Common hard-coded secret patterns and selected unsafe password-hashing practices |
| **Authorized runtime** | Explicit authorization assertions, bounded OpenAPI GET/HEAD discovery, opt-in synthetic identities and configured adversarial scenarios |
| **Review and CI** | JSON, Markdown and SARIF 2.1.0, fingerprints, baselines, diffs, graphs, scores and a local report dashboard |

REAPER does **not** execute the target application's code during a source scan. Dynamic code, unusual middleware, framework-specific data paths and arbitrary SQL policy logic can require manual review.

## Typical workflow

### 1. Scan the application

```sh
reaper scan ./your-app --format json --output reaper.json
reaper report reaper.json --format markdown --output review.md
reaper report reaper.json --format sarif --output reaper.sarif
```

Results include a rule ID, severity, confidence, evidence location and a stable fingerprint. Use `reaper explain` with an ID from the generated report to inspect a finding.

### 2. Add a CI gate

```sh
reaper scan ./your-app --fail-on high
```

| Exit code | Meaning |
| --- | --- |
| `0` | Completed without failing the configured gate |
| `1` | A finding reached the configured severity threshold |
| `2` | Invalid input, operational error or incomplete analysis |

Baselines let teams acknowledge reviewed findings without deleting them:

```sh
reaper baseline reaper.json --output baseline.json
reaper scan ./your-app --baseline baseline.json --fail-on high
```

A passing gate means the configured checks passed—not that the application is secure.

### 3. Inspect PostgreSQL when appropriate

Provide a **dedicated, least-privilege connection** through an environment variable. Database credentials are not accepted as command-line values.

```sh
reaper schema --db-env DATABASE_URL --output catalog.json
reaper rls --db-env DATABASE_URL --format json --output rls.json
reaper scan ./your-app --db-env DATABASE_URL --format json --output combined.json
```

Catalog inspection uses read-only transactions; it does not read application rows or run migrations. Only connect to databases you own or are authorized to assess.

### 4. Review and share the result

```sh
reaper dashboard reaper.json --output reaper-dashboard.html
reaper graph reaper.json --format dot --output data-flow.dot
reaper diff previous.json reaper.json
```

Reports may include sensitive architecture and access-control metadata. Handle them as internal security artifacts.

## Configuration

Use a data-only `reaper.config.ts` in the scan root to declare application-specific resource ownership and tenant fields:

```ts
export default {
  resources: {
    invoice: {
      ownership: ["userId"],
      tenant: ["organizationId"],
    },
  },
  principalPaths: ["req.user.id", "req.user.organizationId"],
};
```

REAPER parses this configuration as literal data; it does not execute it. For trusted middleware contracts, suppression syntax, supported models and rule extensions, see [rules and configuration](docs/rules.md).

## Authorized runtime testing

REAPER also offers security validation against **systems you control or have explicit permission to test**. These modes are distinct from a regular source scan.

- `verify` checks user-defined authorization expectations. Remote targets require an exact-origin allowlist; discovery and request volume are bounded.
- `attack` runs configured, stateful authorization scenarios with target restrictions, acknowledgement/reference, request budgets and cleanup requirements. It is not an unrestricted exploit engine.
- `timing-sqli` provides a **localhost-only DVWA laboratory** for timing-differential observations. It does not scan arbitrary remote sites or establish data exfiltration.

Read the [authorized testing safety contract](docs/offensive-safety-contract.md) and [local timing laboratory guide](docs/timing-sqli.md) before using these commands. Production mutation restrictions and strict runner prerequisites are enforced separately.

## Platform status

The public CLI/library works independently of a hosted service. The repository additionally contains a workspace-scoped PostgreSQL control plane, API-key authentication, an operator dashboard, a restricted staging runner and infrastructure code for an isolated execution plane.

| Surface | Status |
| --- | --- |
| CLI, static analysis and local reports | Usable and tested |
| Local authorization tests and controlled labs | Available with the required configuration and permission |
| Workspace staging and operator dashboard | Development/staging infrastructure; not a public customer SaaS |
| Google Cloud isolated commercial runners | Infrastructure code and checks exist; live deployment and packet-level enforcement are not certified |
| Customer SSO/MFA, billing, backup restoration drills and independent pentest | Not complete |

The strict runner contract rejects execution without the required isolation capabilities; environment flags or successful unit tests alone do not prove that cloud-level isolation exists. See [runner isolation](docs/runner-isolation.md), [GCP deployment](infra/gcp/README.md) and [operator access](docs/operator-access.md).

## Evidence and development

The project CI runs quality checks on Node.js 22/24 and Windows, PostgreSQL integration tests, CLI packaging checks, and a runner-image build. Supply-chain evidence is documented separately. Check the [latest workflow execution](https://github.com/WessYu/REAPER/actions/workflows/ci.yml) for the status of a specific commit.

An archived [real CLI fixture run](https://github.com/WessYu/REAPER/actions/runs/38094079292) demonstrates the earlier vulnerable/secure comparison. It is historical evidence, **not** the result of the latest commit.

To reproduce the current repository checks:

```sh
npm ci --ignore-scripts
npm run check
npm run benchmark:fixtures
```

The [seeded detection benchmark](docs/detection-benchmark.md) evaluates three known issue categories against vulnerable and secure fixtures. Its small sample is a regression check, not a real-world accuracy claim.

## Documentation

- [Rules and configuration](docs/rules.md)
- [Authorization and offensive safety](docs/offensive-safety-contract.md)
- [PostgreSQL and commercial architecture boundaries](docs/commercial-architecture.md)
- [Runner isolation](docs/runner-isolation.md)
- [Staging restrictions](docs/free-staging.md)
- [Operator access and report exports](docs/operator-access.md)
- [Signed rule packs](docs/rule-packs.md)
- [Supply-chain evidence](docs/supply-chain.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

REAPER is published under the [MIT License](LICENSE). It is under active development, and security-critical findings should be validated in their application context.
