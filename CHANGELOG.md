# Changelog

## 0.2.0 — unreleased

- Bounded attack-mode JSON capture to 64 KiB using incremental stream reads, including chunked responses without `Content-Length`; request timeouts now remain active through response processing, and rejected budget reservations no longer inflate request counts.
- Added optional Ed25519 signed authorization scopes with canonical payload signing, exact target/assessment/environment binding, expiry, permission checks, request/cleanup/rate caps, and a global deadline for strict attack runs.
- Added a bounded child-process attack-job API, credential-provider boundary and recursive redaction for values used as identity tokens, cookies or headers.
- Added Ed25519-signed, versioned data-only rule packs with strict literal-match schema, compatibility checks and bounded source scanning; arbitrary JavaScript Rule SDK callbacks remain trusted local code.
- Added CI dependency-audit gating, CycloneDX SBOM generation, SHA-256 artifact manifests, and GitHub artifact attestations on version-tag workflows.
- Added an implementation-backed threat model and documented the current Community/Commercial/Enterprise architecture boundaries and unimplemented controls.
- Added persistent execution journals with integrity validation, write-ahead cleanup plans, bounded crash-recovery APIs and SIGKILL recovery tests.
- Added atomic signed-scope nonce replay protection, including concurrent-consumption regression tests.
- Added persistent hash-chained audit storage with bounded sanitization, serialized appends, tamper detection and truncation detection.
- Added organization/workspace/project authorization boundaries plus a PostgreSQL control-plane schema with workspace RLS and cross-tenant integration tests.
- Added strict runner-isolation capability contracts that fail closed without filesystem, network and enforceable resource-limit capabilities; actual OS/container isolation remains deployment-dependent.
- Added trusted-key lifecycle metadata and revocation/not-before/not-after enforcement for scope and signed rule-pack verification.
- Added release-evidence validation so PR CI checks package/SBOM/hash readiness while GitHub attestations remain restricted to trusted version-tag workflows.
- Expanded bounded control-flow analysis across loops, try/catch/finally and switch with conservative environment merges.
- Added shared-object/property mutation tracking, deeper alias propagation, `.bind`/`.call`/`.apply`, common `Object.assign`/`Object.defineProperty` and `Reflect.get`/`Reflect.set` modeling, and array mutation tracking for supported values.
- Added sequentially resolved Express/Fastify route middleware analysis plus literal contracts for opaque middleware that establishes trusted request principals.
- Added Supabase Storage bucket/operation graph discovery and source-to-PostgreSQL Storage/RLS correlation.
- Added PostgreSQL view/materialized-view dependency and trigger introspection, client-facing view and SECURITY DEFINER trigger posture findings, and dynamic-SQL review for broadly executable SECURITY DEFINER functions.
- Added common symbolic RLS expression classification for identity, tenant/JWT, role-only and constant predicates, bounded boolean composition, and permissive/restrictive PostgreSQL policy reasoning.
- Added bounded OpenAPI GET/HEAD discovery and optional active safe-route probing for localhost/exact-allowlisted targets.
- Added explicit synthetic setup/teardown scenarios plus optional two-to-four-user provisioning from configured signup/cleanup templates, with mutation opt-in, bounded JSON capture and in-memory token/ID variables.
- Added an explicit project control-flow graph exporter (JSON/DOT), a self-contained HTML dashboard and localhost-only REST review service.
- Added a programmatic Rule SDK with deterministic finding emission.
- Added an explicitly authorized stateful attack runner with identity switching, variable capture, exact-origin scope, known-resource authorization confirmation, cleanup requirements, audit events, rate/request/time budgets, DNS-change detection and a server-error circuit breaker.
- Added `REAPER-ATTACK-001` for confirmed violations of operator-declared denial policies in ownership, tenant and vertical-authorization scenarios.
- Added bounded ownership/tenant authorization matrices that test configured identities only against explicitly declared foreign-owned resources, with optional resource-bound JSON proof.
- Tightened confirmation semantics: 5xx responses are inconclusive, confirmation defaults to 2xx, optional `confirmStatuses` narrows acceptance, and `jsonEquals` can prove selected returned resource fields without retaining response bodies.
- Added attack/source correlation through `--input`, carrying confirmed runtime paths into matching source routes, reachable data resources and related static/catalog rule evidence.
- Added expiring production authorization windows, explicit private-network opt-in, cookie-session capture/reuse and secret-backed custom identity headers with protocol-sensitive header blocking.
- Expanded offensive audit metadata with run IDs, authorization references, cleanup-request counts and explicit cleanup-failure events.
- Pinned attack-mode network connections to the initially approved DNS resolution, hard-blocked link-local/unspecified/multicast/reserved infrastructure addresses, and kept private-network access behind explicit opt-in.
- Added a separate bounded cleanup request reserve, best-effort cleanup after cancellation and continuous authorization-expiry enforcement during long-running attack scenarios.
- Expanded tests for middleware, alias/property mutation, Storage, RLS classification, views, triggers, discovery, synthetic lifecycle, dashboard, REST service and custom rules.
- Kept runtime and database boundaries conservative: no arbitrary internet crawling, credential brute force, automatic destructive requests or project-code execution during static scanning.

## 0.1.1 — 2026-10-08

- Fixed npm executable packaging by shipping a stable `bin/reaper.js` wrapper, so the `reaper` command is created even when `dist/` does not exist before `prepack` runs.
- Kept `prepack` building the TypeScript output before the package tarball is finalized.

## 0.1.0 — 2026-10-08

- Added bounded TypeScript AST analysis, inter-file direct-call expansion and request-to-query evidence.
- Added SQL text, unrestricted mutation, ownership and tenant-isolation review rules with direct post-query deny-guard proofs.
- Added Prisma analysis plus data-access discovery for Supabase JS, Drizzle, Knex and node-postgres.
- Added Supabase service-role exposure detection plus optional source-to-PostgreSQL table/RLS/grant and RPC/SECURITY DEFINER correlation.
- Added PostgreSQL read-only catalog introspection for RLS, inherited roles, table/schema/column grants and SECURITY DEFINER posture.
- Added SQL migration checks for RLS removal, policy drops and broad grants.
- Added focused secret/password-crypto checks without retaining secret values in findings.
- Added terminal, JSON, Markdown and SARIF output, stable fingerprints, baselines, suppressions, report diffs and detailed explanations.
- Added JSON/DOT data-access graphs and an explainable provisional security score.
- Added bounded, assertion-driven runtime verification for authorized localhost/allowlisted targets using GET/HEAD only.
- Added secure/vulnerable fixtures, adversarial authorization tests, PostgreSQL integration tests, runtime-verification tests and Node 22/24 package-install CI.

This is an experimental implementation milestone, not a production stability declaration. Version 0.1.1 is published on npm as `@wess2001/reaper`.
