import type { GraphEdge, GraphNode, ScanResult } from "./model.js";

type Graph = ScanResult["graph"];

function dotEscape(value: string): string {
  return value
    .replaceAll("\\", "\\\\")
    .replaceAll('"', '\\"')
    .replaceAll("\n", "\\n");
}

export function renderGraph(graph: Graph, format: string): string {
  if (format === "json") return JSON.stringify(graph, null, 2) + "\n";
  if (format !== "dot") throw new Error("Graph format must be json or dot.");

  const nodes = [...graph.nodes].sort((a, b) => a.id.localeCompare(b.id));
  const edges = [...graph.edges].sort(
    (a, b) =>
      a.from.localeCompare(b.from) ||
      a.to.localeCompare(b.to) ||
      a.relation.localeCompare(b.relation),
  );
  const lines = ["digraph REAPER {", "  rankdir=LR;"];
  for (const node of nodes)
    lines.push(
      '  "' +
        dotEscape(node.id) +
        '" [label="' +
        dotEscape(node.label) +
        "\\n" +
        dotEscape(node.kind) +
        '"];',
    );
  for (const edge of edges)
    lines.push(
      '  "' +
        dotEscape(edge.from) +
        '" -> "' +
        dotEscape(edge.to) +
        '" [label="' +
        dotEscape(edge.relation) +
        '"];',
    );
  lines.push("}");
  return lines.join("\n") + "\n";
}

export type { GraphNode, GraphEdge };
