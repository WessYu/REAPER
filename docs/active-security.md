# Active security

REAPER active security is designed for authorized validation of identity-to-data boundaries. It is deliberately scenario-driven: the operator defines who the principals are, which target and paths are in scope, which state may be created, what denial or invariant is expected, and how synthetic state is cleaned up.

It is not an autonomous penetration-testing agent and does not treat a broad scanner result as permission to send active traffic.

## Safety model

An active run has four independent gates:

1. **target authorization** — `attack.scope.authorized` must be explicitly true;
2. **network scope** — localhost is permitted automatically; remote targets require an exact `allowedTargets` origin and an `authorizationId`;
3. **request scope** — optional `pathPrefixes` prevent scenarios from leaving approved application areas;
4. **impact scope** — mutations require `allowMutations: true`, have a separate mutation budget, and production adds another explicit mutation-consent gate.

Production additionally requires `allowProduction: true`, an authorization identifier and an expiry timestamp. Production mutation runs require `allowProductionMutations: true`. The validator caps explicitly configured production mutation budgets at five requests and production rate limits at five requests per second. The runtime default production mutation budget is lower than non-production.

All active traffic uses manual redirect handling, per-request timeouts, total request budgets, rate limits, cancellation and a configurable server-error circuit breaker.

## Scenario lifecycle

A scenario is:

```text
setup → attack expectation → cleanup
```

Setup and cleanup are exact operator-supplied requests. Cleanup runs in reverse order even when the active assertion confirms a finding or becomes incomplete.

Captured JSON values are held in memory and can be referenced with `{{VARIABLE}}` in later paths, bodies and configured non-sensitive headers. Environment values use `$env:NAME` inside literal body/header/multipart values.

Identity material is separated from normal headers. Bearer tokens and cookies come from `authEnv`/`authVar` and `cookieEnv`/`cookieVar`. Direct Authorization and Cookie header injection is rejected.

## Identity matrix

Identities can declare:

- role;
- numeric `privilegeLevel` from 0–100;
- tenant;
- bearer-token source;
- cookie source.

`reaper attack-matrix --config reaper.config.ts` derives reviewable ownership, cross-tenant and vertical-privilege identity pairs. The numeric privilege level is explicit operator metadata; REAPER does not infer an organization's role hierarchy from names such as `admin` or `user`.

## Scenario classes

The active engine currently models these explicit classes:

- `bola` — cross-user object authorization;
- `tenant` — cross-tenant access;
- `privilege` — vertical authorization boundary;
- `authorization` — generic denial assertion;
- `session` — session-state expectations;
- `cors` — CORS response-policy expectations;
- `csrf` — explicitly modeled cross-site request protection expectations;
- `business` — application-specific status/header/JSON invariants.

These labels affect finding IDs, severity and evidence. They do not cause REAPER to invent attack traffic.

## Expectations

A scenario can declare:

- accepted HTTP statuses;
- expected non-sensitive response headers;
- headers that must remain absent;
- primitive JSON values at explicit paths;
- JSON paths that must remain absent.

Response JSON is only read when a configured expectation requires it and is bounded before parsing. Response bodies are not retained in the report. Sensitive response headers such as Set-Cookie cannot be copied into generic header expectations.

## Synthetic multipart uploads

Active steps can submit bounded `multipart/form-data` with literal/environment-backed fields and synthetic files.

The upload model deliberately does **not** accept local file paths. File contents must be provided explicitly in configuration or through a named environment variable. Filenames reject path separators, file count is bounded, and `attack.maxUploadBytes` caps aggregate synthetic content.

This supports authorization and workflow validation around upload endpoints without silently exfiltrating files from the machine running REAPER.

## Static and database correlation

Run a normal source/database scan first:

```sh
reaper scan ./application --db-env DATABASE_URL --format json --output combined.json
```

Review candidate active paths:

```sh
reaper attack-plan combined.json
reaper attack-matrix --config reaper.config.ts
```

Then run an explicitly configured active scenario:

```sh
reaper attack https://preview.example.com \
  --config reaper.config.ts \
  --input combined.json \
  --format json \
  --output attack-report.json
```

When source evidence is provided, the active result keeps the existing route → query → resource graph and adds principal/request/runtime correlation. Matching authorization, tenant, RLS, privilege and Supabase findings can be attached to the active path. Static evidence remains static; only an observed active invariant violation becomes CONFIRMED.

## Trace instrumentation

Every active request receives a UUID `x-reaper-trace-id`.

Applications may import:

```ts
import {
  currentReaperTraceId,
  reaperTraceMiddleware,
  runWithReaperTrace,
} from "@wess2001/reaper";
```

The helper uses AsyncLocalStorage to propagate valid REAPER UUID trace IDs into asynchronous application work. It is optional and does not grant REAPER access to application secrets or database rows.

## Audit and evidence integrity

Each active request produces an audit event containing bounded metadata: scenario, step, identity name, method, configured path, status, duration and trace ID. Tokens, cookies and response bodies are excluded.

Audit events form a SHA-256 chain:

```sh
reaper audit-verify attack-report.json
```

A separate content-addressed evidence bundle can be built and verified:

```sh
reaper evidence attack-report.json --output reaper-evidence.json
reaper evidence-verify reaper-evidence.json
```

These hashes provide tamper evidence. They are not a digital signature and do not establish who produced the report.

## Security regressions

A confirmed active report can generate a focused regression test:

```sh
reaper regression attack-report.json \
  --config reaper.config.ts \
  --output reaper.attack.regression.mjs
```

The generated test uses the configured environment-variable names, not secret values, and fails if a CONFIRMED Active Security finding remains.

## API surface planning

`reaper openapi-plan` models supplied OpenAPI JSON, including operations, parameters, request content types, declared security and whether an operation is mutating/destructive.

`reaper graphql-plan` models supplied GraphQL introspection JSON, including queries, mutations, subscriptions and identifier-bearing arguments.

These commands are passive. They do not send traffic.

## Callback canaries

`reaper callback` starts a loopback-only callback collector:

```sh
reaper callback local-canary --port 7338
```

It binds to `127.0.0.1`, issues a random UUID callback URL and records method/path/user-agent/content-type metadata for GET, HEAD or POST. Authorization, Cookie and request bodies are deliberately not recorded.

This is useful for local or CI canaries. It is not hosted OAST infrastructure and cannot prove callbacks from systems that cannot reach the REAPER host.

## Current boundaries

The active engine intentionally does not claim:

- autonomous credential guessing or brute force;
- unrestricted injection payload generation;
- browser-executed XSS proof;
- arbitrary destructive workflows;
- WebSocket protocol attack automation;
- public hosted OAST infrastructure;
- automatic MFA/CAPTCHA bypass;
- arbitrary local-file upload;
- a hardened third-party plugin sandbox;
- enterprise SSO/RBAC/control-plane features;
- cryptographically signed release/report identity.

Those require dedicated implementations and should not be represented by shallow rules or marketing labels.
