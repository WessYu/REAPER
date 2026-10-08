import ts from "typescript";
import { readFile, realpath } from "node:fs/promises";
import path from "node:path";
import { discover } from "./project.js";
import { validateConfig } from "./config.js";
import type { Config, Diagnostic } from "./model.js";

export type ControlFlowEdgeKind =
  | "next"
  | "true"
  | "false"
  | "back"
  | "case"
  | "default"
  | "break"
  | "continue"
  | "try"
  | "catch"
  | "finally";

export interface ControlFlowNode {
  id: string;
  file: string;
  line: number;
  column: number;
  kind: "entry" | "statement" | "branch" | "loop" | "exit";
  label: string;
}

export interface ControlFlowEdge {
  from: string;
  to: string;
  kind: ControlFlowEdgeKind;
}

export interface ControlFlowGraph {
  nodes: ControlFlowNode[];
  edges: ControlFlowEdge[];
  diagnostics: Diagnostic[];
}

interface BuildContext {
  source: ts.SourceFile;
  file: string;
  nodes: ControlFlowNode[];
  edges: ControlFlowEdge[];
  breakTarget?: string;
  continueTarget?: string;
}

function nodeId(file: string, node: ts.Node, suffix = ""): string {
  return `cfg:${file}:${node.pos}:${node.end}${suffix}`;
}

function location(
  source: ts.SourceFile,
  node: ts.Node,
): {
  line: number;
  column: number;
} {
  const value = source.getLineAndCharacterOfPosition(node.getStart(source));
  return { line: value.line + 1, column: value.character + 1 };
}

function shortLabel(node: ts.Node, source: ts.SourceFile): string {
  const text = node.getText(source).replace(/\s+/g, " ").trim();
  return text.length > 120 ? text.slice(0, 117) + "..." : text;
}

function addNode(
  context: BuildContext,
  node: ts.Node,
  kind: ControlFlowNode["kind"],
  label?: string,
  suffix = "",
): string {
  const id = nodeId(context.file, node, suffix);
  if (!context.nodes.some((candidate) => candidate.id === id)) {
    context.nodes.push({
      id,
      file: context.file,
      ...location(context.source, node),
      kind,
      label: label ?? shortLabel(node, context.source),
    });
  }
  return id;
}

function edge(
  context: BuildContext,
  from: string,
  to: string | undefined,
  kind: ControlFlowEdgeKind,
): void {
  if (!to) return;
  const value = { from, to, kind };
  if (
    !context.edges.some(
      (candidate) =>
        candidate.from === value.from &&
        candidate.to === value.to &&
        candidate.kind === value.kind,
    )
  )
    context.edges.push(value);
}

function buildBlock(
  statements: readonly ts.Statement[],
  next: string | undefined,
  context: BuildContext,
): string | undefined {
  let current = next;
  for (let index = statements.length - 1; index >= 0; index--)
    current = buildStatement(statements[index]!, current, context);
  return current;
}

function buildStatement(
  statement: ts.Statement,
  next: string | undefined,
  context: BuildContext,
): string {
  if (ts.isBlock(statement)) {
    const id = addNode(context, statement, "statement", "{ block }", ":block");
    const inner = buildBlock(statement.statements, next, context);
    edge(context, id, inner ?? next, "next");
    return id;
  }

  if (ts.isIfStatement(statement)) {
    const id = addNode(
      context,
      statement.expression,
      "branch",
      `if (${shortLabel(statement.expression, context.source)})`,
      ":if",
    );
    const yes = buildStatement(statement.thenStatement, next, context);
    const no = statement.elseStatement
      ? buildStatement(statement.elseStatement, next, context)
      : next;
    edge(context, id, yes, "true");
    edge(context, id, no, "false");
    return id;
  }

  if (
    ts.isWhileStatement(statement) ||
    ts.isDoStatement(statement) ||
    ts.isForStatement(statement) ||
    ts.isForInStatement(statement) ||
    ts.isForOfStatement(statement)
  ) {
    const condition = ts.isForStatement(statement)
      ? statement.condition
      : ts.isForInStatement(statement) || ts.isForOfStatement(statement)
        ? statement.expression
        : statement.expression;
    const label = ts.isForStatement(statement)
      ? `for (${statement.initializer?.getText(context.source) ?? ""}; ${statement.condition?.getText(context.source) ?? ""}; ${statement.incrementor?.getText(context.source) ?? ""})`
      : ts.isForInStatement(statement) || ts.isForOfStatement(statement)
        ? shortLabel(statement, context.source).split("{", 1)[0]!.trim()
        : `${ts.isDoStatement(statement) ? "do/while" : "while"} (${condition?.getText(context.source) ?? ""})`;
    const id = addNode(context, statement, "loop", label, ":loop");
    const loopContext: BuildContext = {
      ...context,
      breakTarget: next,
      continueTarget: id,
    };
    const body = buildStatement(statement.statement, id, loopContext);
    edge(context, id, body, "true");
    edge(context, id, next, "false");
    return id;
  }

  if (ts.isSwitchStatement(statement)) {
    const id = addNode(
      context,
      statement.expression,
      "branch",
      `switch (${shortLabel(statement.expression, context.source)})`,
      ":switch",
    );
    const switchContext: BuildContext = {
      ...context,
      breakTarget: next,
    };
    for (const clause of statement.caseBlock.clauses) {
      const entry = buildBlock(clause.statements, next, switchContext);
      if (entry)
        edge(
          context,
          id,
          entry,
          ts.isDefaultClause(clause) ? "default" : "case",
        );
    }
    if (!statement.caseBlock.clauses.some(ts.isDefaultClause))
      edge(context, id, next, "default");
    return id;
  }

  if (ts.isTryStatement(statement)) {
    const id = addNode(context, statement, "branch", "try", ":try");
    const finalEntry = statement.finallyBlock
      ? buildBlock(statement.finallyBlock.statements, next, context)
      : next;
    const tryEntry = buildBlock(
      statement.tryBlock.statements,
      finalEntry,
      context,
    );
    edge(context, id, tryEntry, "try");
    if (statement.catchClause) {
      const catchEntry = buildBlock(
        statement.catchClause.block.statements,
        finalEntry,
        context,
      );
      edge(context, id, catchEntry, "catch");
    }
    if (statement.finallyBlock && finalEntry)
      edge(context, id, finalEntry, "finally");
    return id;
  }

  const id = addNode(
    context,
    statement,
    ts.isReturnStatement(statement) || ts.isThrowStatement(statement)
      ? "exit"
      : "statement",
  );
  if (ts.isReturnStatement(statement) || ts.isThrowStatement(statement))
    return id;
  if (ts.isBreakStatement(statement)) {
    edge(context, id, context.breakTarget, "break");
    return id;
  }
  if (ts.isContinueStatement(statement)) {
    edge(context, id, context.continueTarget, "continue");
    return id;
  }
  edge(context, id, next, "next");
  return id;
}

function functionName(
  node: ts.FunctionLikeDeclaration,
  source: ts.SourceFile,
): string {
  const named = "name" in node ? node.name : undefined;
  if (named && ts.isIdentifier(named)) return named.text;
  if (
    (ts.isArrowFunction(node) || ts.isFunctionExpression(node)) &&
    node.parent &&
    ts.isVariableDeclaration(node.parent) &&
    ts.isIdentifier(node.parent.name)
  )
    return node.parent.name.text;
  return `anonymous@${location(source, node).line}`;
}

function buildSourceFile(
  file: string,
  source: ts.SourceFile,
): ControlFlowGraph {
  const nodes: ControlFlowNode[] = [];
  const edges: ControlFlowEdge[] = [];
  const context: BuildContext = { source, file, nodes, edges };

  function visit(node: ts.Node): void {
    if (
      (ts.isFunctionDeclaration(node) ||
        ts.isFunctionExpression(node) ||
        ts.isArrowFunction(node) ||
        ts.isMethodDeclaration(node)) &&
      node.body &&
      ts.isBlock(node.body)
    ) {
      const entry = addNode(
        context,
        node,
        "entry",
        `function ${functionName(node, source)}`,
        ":entry",
      );
      const body = buildBlock(node.body.statements, undefined, context);
      edge(context, entry, body, "next");
    }
    ts.forEachChild(node, visit);
  }

  visit(source);
  return { nodes, edges, diagnostics: [] };
}

export async function buildProjectCfg(
  root: string,
  config: Config = {},
): Promise<ControlFlowGraph> {
  const resolved = await realpath(root);
  const diagnostics: Diagnostic[] = [];
  const normalized = validateConfig(config);
  const files = await discover(resolved, normalized, diagnostics);
  const nodes: ControlFlowNode[] = [];
  const edges: ControlFlowEdge[] = [];
  for (const file of files.filter((value) => /\.[cm]?[jt]sx?$/.test(value))) {
    const text = await readFile(file, "utf8");
    const source = ts.createSourceFile(
      file,
      text,
      ts.ScriptTarget.Latest,
      true,
      file.endsWith(".tsx") || file.endsWith(".jsx")
        ? ts.ScriptKind.TSX
        : file.endsWith(".js") || file.endsWith(".mjs") || file.endsWith(".cjs")
          ? ts.ScriptKind.JS
          : ts.ScriptKind.TS,
    );
    const relative = path.relative(resolved, file).replaceAll("\\", "/");
    const graph = buildSourceFile(relative, source);
    nodes.push(...graph.nodes);
    edges.push(...graph.edges);
    const parseDiagnostics =
      (
        source as ts.SourceFile & {
          parseDiagnostics?: readonly ts.Diagnostic[];
        }
      ).parseDiagnostics ?? [];
    for (const diagnostic of parseDiagnostics)
      diagnostics.push({
        file: relative,
        message: ts.flattenDiagnosticMessageText(diagnostic.messageText, " "),
      });
  }
  return {
    nodes,
    edges,
    diagnostics,
  };
}

export function renderControlFlowGraph(
  graph: ControlFlowGraph,
  format: "json" | "dot" = "json",
): string {
  if (format === "json") return JSON.stringify(graph, null, 2) + "\n";
  const escape = (value: string) =>
    value.replaceAll("\\", "\\\\").replaceAll('"', '\\"');
  return (
    "digraph REAPER_CFG {\n" +
    '  rankdir="LR";\n' +
    graph.nodes
      .map(
        (node) =>
          `  "${escape(node.id)}" [label="${escape(node.label)}\\n${escape(node.file)}:${node.line}"];\n`,
      )
      .join("") +
    graph.edges
      .map(
        (value) =>
          `  "${escape(value.from)}" -> "${escape(value.to)}" [label="${value.kind}"];\n`,
      )
      .join("") +
    "}\n"
  );
}
