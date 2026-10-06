# Changelog

## 0.1.0 — unreleased

- Added bounded TypeScript AST analysis, inter-file direct-call expansion and request-to-query evidence.
- Added SQL text, unrestricted mutation, ownership and tenant-isolation review rules with direct post-query deny-guard proofs.
- Added Prisma analysis plus data-access discovery for Supabase JS, Drizzle, Knex and node-postgres.
- Added Supabase service-role exposure detection and optional source-to-PostgreSQL table/RLS/grant correlation.
- Added PostgreSQL read-only catalog introspection for RLS, inherited roles, table/schema/column grants and SECURITY DEFINER posture.
- Added SQL migration checks for RLS removal, policy drops and broad grants.
- Added focused secret/password-crypto checks without retaining secret values in findings.
- Added terminal, JSON, Markdown and SARIF output, stable fingerprints, baselines, suppressions, report diffs and detailed explanations.
- Added JSON/DOT data-access graphs and an explainable provisional security score.
- Added bounded, assertion-driven runtime verification for authorized localhost/allowlisted targets using GET/HEAD only.
- Added secure/vulnerable fixtures, adversarial authorization tests, PostgreSQL integration tests, runtime-verification tests and Node 22/24 package-install CI.

This is an experimental implementation milestone, not a production stability declaration or npm publication.
