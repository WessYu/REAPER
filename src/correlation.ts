import { finding } from "./findings.js";
import {
  broadGrant,
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
