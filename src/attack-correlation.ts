import type { GraphNode, ScanResult } from "./model.js";

function normalizedRoute(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const match = value.trim().match(/^([A-Z]+)\s+(.+)$/i);
  if (!match) return undefined;
  const method = match[1]!.toUpperCase();
  const path = match[2]!
    .replace(/\{\{[A-Za-z_][A-Za-z0-9_]*\}\}/g, "*")
    .replace(/:[A-Za-z_][A-Za-z0-9_]*/g, "*")
    .replace(/\{[A-Za-z_][A-Za-z0-9_]*\}/g, "*")
    .replace(/\/+$/, "") || "/";
  return `${method} ${path}`;
}

function reachableResources(
  source: ScanResult,
  routeNode: GraphNode,
): GraphNode[] {
  const byId = new Map(source.graph.nodes.map((node) => [node.id, node]));
  const queue = [routeNode.id];
  const seen = new Set(queue);
  const resources: GraphNode[] = [];
  for (let depth = 0; queue.length && depth < 4; depth++) {
    const width = queue.length;
    for (let index = 0; index < width; index++) {
      const current = queue.shift()!;
      for (const edge of source.graph.edges.filter(
        (candidate) => candidate.from === current,
      )) {
        if (seen.has(edge.to)) continue;
        seen.add(edge.to);
        const node = byId.get(edge.to);
        if (!node) continue;
        if (node.kind === "resource") resources.push(node);
        else queue.push(node.id);
      }
    }
  }
  return [...new Map(resources.map((node) => [node.id, node])).values()];
}

export function correlateAttackSource(
  attack: ScanResult,
  source: ScanResult,
): ScanResult {
  const routeNodes = source.graph.nodes.filter((node) => node.kind === "route");
  const sourceFindings = source.findings.filter(
    (finding) => finding.status !== "suppressed",
  );

  for (const finding of attack.findings.filter(
    (item) => item.ruleId === "REAPER-ATTACK-001",
  )) {
    const normalized = normalizedRoute(finding.route);
    if (!normalized) continue;
    const matches = routeNodes.filter(
      (node) => normalizedRoute(node.label) === normalized,
    );
    for (const route of matches) {
      const evidence = `Correlated source route: ${route.label}`;
      if (!finding.evidence.includes(evidence)) finding.evidence.push(evidence);
      for (const resource of reachableResources(source, route)) {
        const resourceEvidence = `Correlated source data resource: ${resource.label}`;
        if (!finding.evidence.includes(resourceEvidence))
          finding.evidence.push(resourceEvidence);
      }
      const relatedRules = sourceFindings
        .filter(
          (candidate) =>
            normalizedRoute(candidate.route) === normalized &&
            candidate.ruleId !== finding.ruleId,
        )
        .map((candidate) => candidate.ruleId);
      for (const ruleId of [...new Set(relatedRules)]) {
        const ruleEvidence = `Correlated static/catalog finding: ${ruleId}`;
        if (!finding.evidence.includes(ruleEvidence))
          finding.evidence.push(ruleEvidence);
      }
    }
  }

  for (const node of source.graph.nodes)
    if (!attack.graph.nodes.some((candidate) => candidate.id === node.id))
      attack.graph.nodes.push(node);
  for (const edge of source.graph.edges)
    if (
      !attack.graph.edges.some(
        (candidate) =>
          candidate.from === edge.from &&
          candidate.to === edge.to &&
          candidate.relation === edge.relation,
      )
    )
      attack.graph.edges.push(edge);

  attack.coverage.source ||= source.coverage.source;
  attack.coverage.database ||= source.coverage.database;
  return attack;
}

export { normalizedRoute as normalizeAttackRoute };
