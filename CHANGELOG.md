# Changelog

## 0.2.0 — unreleased

- Expanded bounded control-flow analysis across loops, try/catch/finally and switch with conservative environment merges.
- Added shared-object/property mutation tracking, deeper alias propagation, direct `.call`/`.apply` support and array mutation tracking for supported values.
- Added sequentially resolved Express/Fastify route middleware analysis before handler evaluation.
- Added Supabase Storage bucket/operation graph discovery and source-to-PostgreSQL Storage/RLS correlation.
- Added PostgreSQL view/materialized-view and trigger introspection plus client-facing view and SECURITY DEFINER trigger posture findings.
- Added common symbolic RLS expression classification for identity, tenant/JWT, role-only and constant predicates.
- Added bounded OpenAPI GET/HEAD discovery for localhost/exact-allowlisted targets.
- Added explicit synthetic setup/teardown scenarios with mutation opt-in, bounded JSON capture, in-memory token/ID variables and cleanup.
- Added a self-contained HTML dashboard and localhost-only REST review service.
- Added a programmatic Rule SDK with deterministic finding emission.
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
