import { finding } from "./findings.js";
import {
  broadGrant,
  classifyPolicyExpression,
  effectiveTableGrants,
  unsafeSecurityDefinerSearchPath,
} from "./postgres.js";
import type { DatabaseSnapshot } from "./postgres.js";
import type { Finding, GraphNode, ScanResult } from "./model.js";

function queryLocation(node: GraphNode): {
  file: string;
  line: number;
  column: number;
} | null {
  const match = node.id.match(/^query:(.+):(\d+):(\d+)$/);
  if (!match) return null;
  return {
    file: match[1]!,
    line: Number(match[2]),
    column: Number(match[3]),
  };
}

function operationPrivilege(label: string): string | undefined {
  if (label.endsWith(".select")) return "SELECT";
  if (label.endsWith(".insert")) return "INSERT";
  if (label.endsWith(".update") || label.endsWith(".upsert")) return "UPDATE";
  if (label.endsWith(".delete")) return "DELETE";
  return undefined;
}

export function correlateSourceDatabase(
  result: ScanResult,
  snapshot: DatabaseSnapshot,
): Finding[] {
  const findings: Finding[] = [];
  const nodes = new Map(result.graph.nodes.map((node) => [node.id, node]));
  const routeByQuery = new Map<string, string>();
  for (const edge of result.graph.edges) {
    if (edge.relation !== "calls" || !edge.to.startsWith("query:")) continue;
    const route = nodes.get(edge.from);
    if (route?.kind === "route") routeByQuery.set(edge.to, route.label);
  }

  for (const edge of result.graph.edges) {
    if (edge.relation !== "accesses") continue;
    const query = nodes.get(edge.from);
    const resourceNode = nodes.get(edge.to);
    if (
      !query ||
      query.kind !== "query" ||
      !query.label.startsWith("supabase.") ||
      !resourceNode ||
      resourceNode.kind !== "resource"
    )
      continue;

    if (resourceNode.label.startsWith("storage:")) {
      const bucket = resourceNode.label.slice("storage:".length);
      const loc = queryLocation(query);
      if (!loc) continue;
      const table = snapshot.tables.find(
        (candidate) =>
          candidate.schema === "storage" && candidate.name === "objects",
      );
      if (!table) continue;
      const route = routeByQuery.get(query.id);
      const resource = `storage.objects bucket ${bucket}`;
      const grants = effectiveTableGrants(
        snapshot,
        "storage",
        "objects",
      ).filter((grant) =>
        ["SELECT", "INSERT", "UPDATE", "DELETE"].includes(grant.privilege),
      );
      if (grants.length && !table.rls)
        findings.push(
          finding(
            {
              ...loc,
              ruleId: "REAPER-STORAGE-003",
              title:
                "Supabase Storage client path reaches storage.objects without RLS",
              description: `Observed ${query.label} against bucket ${bucket}; storage.objects has effective broad DML/SELECT access and RLS is disabled.`,
              severity: "HIGH",
              confidence: "HIGH",
              category: "Supabase",
              cwe: 862,
              route,
              resource,
              evidence: [
                `Storage bucket: ${bucket}`,
                `Source operation: ${query.label}`,
                `Effective broad grants: ${[
                  ...new Set(
                    grants.map(
                      (grant) => `${grant.role}:${grant.privilege}`,
                    ),
                  ),
                ].join(", ")}`,
                "storage.objects row-level security is disabled.",
              ],
              dataFlow: [{ ...loc, kind: "sink", label: query.label }],
              recommendation:
                "Enable RLS on storage.objects and define reviewed bucket/ownership policies before exposing this Storage path to client roles.",
            },
            `storage-db:${query.id}:${bucket}:no-rls`,
          ),
        );

      const openPolicies = snapshot.policies.filter(
        (policy) =>
          policy.schema === "storage" &&
          policy.table === "objects" &&
          policy.permissive === "PERMISSIVE" &&
          policy.roles.some((role) => broadGrant(snapshot, role)) &&
          [
            classifyPolicyExpression(policy.using),
            classifyPolicyExpression(policy.check),
          ].includes("constant-open"),
      );
      if (table.rls && openPolicies.length)
        findings.push(
          finding(
            {
              ...loc,
              ruleId: "REAPER-STORAGE-004",
              title:
                "Supabase Storage client path is covered by constant-open policy",
              description: `Observed ${query.label} against bucket ${bucket}; a broad permissive storage.objects policy contains a constant-open predicate.`,
              severity: "HIGH",
              confidence: "HIGH",
              category: "Supabase",
              cwe: 862,
              route,
              resource,
              evidence: [
                `Storage bucket: ${bucket}`,
                `Open policies: ${openPolicies.map((policy) => policy.name).join(", ")}`,
              ],
              dataFlow: [{ ...loc, kind: "sink", label: query.label }],
              recommendation:
                "Replace constant-open Storage policies with bucket, ownership or tenant predicates and retest the client path.",
            },
            `storage-db:${query.id}:${bucket}:open-policy`,
          ),
        );
      continue;
    }

    if (resourceNode.label.startsWith("rpc:")) {
      const rpc = resourceNode.label.slice("rpc:".length);
      const loc = queryLocation(query);
      if (!loc) continue;
      const route = routeByQuery.get(query.id);
      for (const fn of snapshot.functions.filter(
        (candidate) => candidate.schema === "public" && candidate.name === rpc,
      )) {
        if (!fn.securityDefiner || !unsafeSecurityDefinerSearchPath(fn))
          continue;
        const broadExecute = fn.executeRoles.filter((role) =>
          broadGrant(snapshot, role),
        );
        if (!broadExecute.length) continue;
        const resource = `${fn.schema}.${fn.name}(${fn.identityArguments})`;
        findings.push(
          finding(
            {
              ...loc,
              ruleId: "REAPER-SUPA-003",
              title:
                "Supabase RPC reaches broadly executable SECURITY DEFINER function with unsafe search_path",
              description: `Observed Supabase RPC ${rpc}; the PostgreSQL snapshot shows a SECURITY DEFINER function executable by a broad client role with an unsafe function search_path.`,
              severity: "HIGH",
              confidence: "HIGH",
              category: "Supabase",
              cwe: 250,
              route,
              resource,
              evidence: [
                `Source data-access operation: ${query.label}`,
                `RPC function: ${resource}`,
                `Effective broad EXECUTE through: ${[
                  ...new Set(broadExecute),
                ].join(", ")}`,
                "The function-local search_path is missing or includes an untrusted schema.",
              ],
              dataFlow: [
                {
                  ...loc,
                  kind: "sink",
                  label: query.label,
                },
              ],
              recommendation:
                "Restrict EXECUTE to intended roles and set a function-local search_path containing only trusted schemas before exposing the RPC to client sessions.",
            },
            `supabase-rpc:${query.id}:${resource}`,
          ),
        );
      }
      continue;
    }

    const privilege = operationPrivilege(query.label);
    if (!privilege) continue;
    const [schema, table] = resourceNode.label.includes(".")
      ? resourceNode.label.split(".", 2)
      : ["public", resourceNode.label];
    if (!schema || !table) continue;
    const tableState = snapshot.tables.find(
      (candidate) => candidate.schema === schema && candidate.name === table,
    );
    if (!tableState) continue;

    const grants = effectiveTableGrants(snapshot, schema, table).filter(
      (grant) => grant.privilege === privilege,
    );
    if (!grants.length || tableState.rls) continue;
    const loc = queryLocation(query);
    if (!loc) continue;
    const resource = `${schema}.${table}`;
    const route = routeByQuery.get(query.id);
    findings.push(
      finding(
        {
          ...loc,
          ruleId: "REAPER-SUPA-002",
          title:
            "Supabase client path reaches broadly granted table without RLS",
          description: `Observed ${query.label} access to ${resource}; the database snapshot shows effective ${privilege} access for a broad client role while RLS is disabled.`,
          severity: "HIGH",
          confidence: "HIGH",
          category: "Supabase",
          cwe: 862,
          route,
          resource,
          evidence: [
            `Source data-access operation: ${query.label}`,
            `Database privilege: ${privilege}`,
            `Effective broad grant through: ${[
              ...new Set(grants.map((grant) => grant.role)),
            ].join(", ")}`,
            "Row-level security is disabled on the reached table.",
          ],
          dataFlow: [
            {
              ...loc,
              kind: "sink",
              label: query.label,
            },
          ],
          recommendation:
            "Enable and review RLS for client-reachable Supabase tables, and restrict grants to the minimum operations required by the intended client roles.",
        },
        `supabase-db:${query.id}:${resource}:${privilege}`,
      ),
    );
  }
  return findings;
}
