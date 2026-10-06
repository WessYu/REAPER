import ts from "typescript";
import path from "node:path";
import { unrestrictedMutation } from "./sql.js";
import { finding } from "./findings.js";
import type {
  Config,
  Evidence,
  Finding,
  Location,
  ScanResult,
} from "./model.js";

type Fn =
  | ts.FunctionDeclaration
  | ts.FunctionExpression
  | ts.ArrowFunction
  | ts.MethodDeclaration;
interface Value {
  text?: string;
  origin?: string;
  principal?: string;
  driver?: string;
  trace: Evidence[];
  fields?: Map<string, Value>;
  items?: Value[];
  fn?: Fn;
  resource?: string;
  resourceField?: string;
  queryKey?: string;
}
type Environment = Map<ts.Symbol, Value>;
const empty = (): Value => ({ trace: [] });
const drivers = new Map([
  ["@prisma/client", "prisma"],
  ["pg", "pg"],
  ["knex", "knex"],
]);
const operations = new Set([
  "findUnique",
  "findUniqueOrThrow",
  "findFirst",
  "findFirstOrThrow",
  "findMany",
  "update",
  "updateMany",
  "delete",
  "deleteMany",
  "count",
  "aggregate",
]);
const fnNode = (node: ts.Node): node is Fn =>
  ts.isFunctionDeclaration(node) ||
  ts.isFunctionExpression(node) ||
  ts.isArrowFunction(node) ||
  ts.isMethodDeclaration(node);
function combine(values: Value[]): Value {
  return {
    trace: [
      ...new Map(
        values.flatMap((v) => v.trace).map((e) => [JSON.stringify(e), e]),
      ).values(),
    ],
  };
}

export function analyze(
  root: string,
  files: string[],
  config: Config,
  result: ScanResult,
): void {
  const scripts = files.filter((f) => !f.endsWith(".prisma"));
  const allowed = new Set(scripts);
  const options: ts.CompilerOptions = {
    allowJs: true,
    noLib: true,
    noResolve: false,
    target: ts.ScriptTarget.Latest,
    module: ts.ModuleKind.NodeNext,
    moduleResolution: ts.ModuleResolutionKind.NodeNext,
  };
  const host = ts.createCompilerHost(options);
  const originalRead = host.readFile;
  host.readFile = (file) =>
    allowed.has(file) ? originalRead(file) : undefined;
  host.fileExists = (file) => allowed.has(file);
  const program = ts.createProgram(scripts, options, host);
  const checker = program.getTypeChecker();
  const visitedSinks = new Set<string>();
  const sinkCounts = new Set<string>();
  const resolving = new Set<ts.Symbol>();
  const pendingAuthorization = new Map<
    string,
    { ownership?: Finding; tenant?: Finding }
  >();
  const defaults = [
    "req.user.id",
    "request.user.id",
    "req.auth.userId",
    "request.auth.userId",
    "req.user.tenantId",
    "request.user.tenantId",
    "req.user.organizationId",
    "request.user.organizationId",
  ];
  const principals = new Set(config.principalPaths ?? defaults);
  const location = (node: ts.Node): Location => {
    const sf = node.getSourceFile();
    const lc = sf.getLineAndCharacterOfPosition(node.getStart());
    return {
      file: path.relative(root, sf.fileName).split(path.sep).join("/"),
      line: lc.line + 1,
      column: lc.character + 1,
    };
  };
  const evidence = (
    node: ts.Node,
    kind: Evidence["kind"],
    label: string,
  ): Evidence => ({ ...location(node), kind, label });
  const symbol = (node: ts.Node): ts.Symbol | undefined =>
    checker.getSymbolAtLocation(node);
  const canonical = (s: ts.Symbol): ts.Symbol =>
    s.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(s) : s;
  function importDriver(s: ts.Symbol): string | undefined {
    for (const declaration of s.declarations ?? []) {
      let node: ts.Node | undefined = declaration;
      while (node && !ts.isImportDeclaration(node)) node = node.parent;
      if (node && ts.isStringLiteral(node.moduleSpecifier))
        return drivers.get(node.moduleSpecifier.text);
    }
    return undefined;
  }
  function resolve(
    node: ts.Node,
    env: Environment,
    route: string | undefined,
    depth: number,
  ): Value {
    const raw = symbol(node);
    if (!raw) return empty();
    if (env.has(raw)) return env.get(raw)!;
    const driver = importDriver(raw);
    if (driver) return { trace: [], driver };
    const s = canonical(raw);
    if (env.has(s)) return env.get(s)!;
    if (resolving.has(s)) return empty();
    resolving.add(s);
    try {
      for (const declaration of s.declarations ?? []) {
        if (fnNode(declaration)) return { trace: [], fn: declaration };
        if (ts.isVariableDeclaration(declaration) && declaration.initializer)
          return evaluate(declaration.initializer, env, route, depth + 1);
      }
      return empty();
    } finally {
      resolving.delete(s);
    }
  }
  function bind(name: ts.BindingName, value: Value, env: Environment): void {
    if (ts.isIdentifier(name)) {
      const s = symbol(name);
      if (s) env.set(s, value);
      return;
    }
    if (ts.isObjectBindingPattern(name))
      for (const entry of name.elements) {
        const key = entry.propertyName?.getText() ?? entry.name.getText();
        bind(entry.name, member(value, key, entry), env);
      }
    else
      name.elements.forEach((entry, i) => {
        if (ts.isBindingElement(entry))
          bind(entry.name, value.items?.[i] ?? empty(), env);
      });
  }
  function member(base: Value, key: string, node: ts.Node): Value {
    if (base.fields?.has(key)) return base.fields.get(key)!;
    const origin = base.origin ? `${base.origin}.${key}` : undefined;
    if (origin && principals.has(origin))
      return { trace: [], principal: origin, origin };
    const source =
      origin &&
      /^(?:req|request)\.(?:params|query|body|headers|cookies)(?:\.|$)/.test(
        origin,
      );
    if (source) return { origin, trace: [evidence(node, "source", origin)] };
    return {
      ...base,
      origin,
      resourceField: base.resource ? key : base.resourceField,
      text: base.text === undefined ? undefined : `${base.text}.${key}`,
    };
  }
  function propertyKey(node: ts.PropertyName): string | undefined {
    return ts.isIdentifier(node) ||
      ts.isStringLiteral(node) ||
      ts.isNumericLiteral(node)
      ? node.text
      : undefined;
  }
  function evaluate(
    node: ts.Expression,
    env: Environment,
    route: string | undefined,
    depth: number,
  ): Value {
    if (depth > 40) {
      result.diagnostics.push({
        ...location(node),
        message: "Analysis depth exceeded; flow incomplete.",
      });
      return empty();
    }
    if (
      ts.isParenthesizedExpression(node) ||
      ts.isAsExpression(node) ||
      ts.isNonNullExpression(node) ||
      ts.isAwaitExpression(node) ||
      ts.isSatisfiesExpression(node)
    )
      return evaluate(node.expression, env, route, depth + 1);
    if (ts.isIdentifier(node)) return resolve(node, env, route, depth);
    if (ts.isStringLiteralLike(node) || ts.isNumericLiteral(node))
      return { trace: [], text: node.text };
    if (ts.isArrowFunction(node) || ts.isFunctionExpression(node))
      return { trace: [], fn: node };
    if (ts.isPropertyAccessExpression(node)) {
      const base = evaluate(node.expression, env, route, depth + 1);
      const value = member(base, node.name.text, node);
      return value.fn ||
        value.origin ||
        value.driver ||
        value.fields ||
        value.trace.length
        ? value
        : resolve(node.name, env, route, depth);
    }
    if (ts.isElementAccessExpression(node)) {
      const key = evaluate(node.argumentExpression, env, route, depth + 1);
      return key.text !== undefined
        ? member(
            evaluate(node.expression, env, route, depth + 1),
            key.text,
            node,
          )
        : combine([evaluate(node.expression, env, route, depth + 1), key]);
    }
    if (ts.isObjectLiteralExpression(node)) {
      const fields = new Map<string, Value>();
      for (const property of node.properties) {
        if (ts.isSpreadAssignment(property)) {
          for (const [k, v] of evaluate(
            property.expression,
            env,
            route,
            depth + 1,
          ).fields ?? [])
            fields.set(k, v);
        }
        if (ts.isPropertyAssignment(property)) {
          const key = propertyKey(property.name);
          if (key)
            fields.set(
              key,
              evaluate(property.initializer, env, route, depth + 1),
            );
        }
        if (ts.isShorthandPropertyAssignment(property)) {
          const s = checker.getShorthandAssignmentValueSymbol(property);
          fields.set(
            property.name.text,
            (s && env.get(s)) ??
              (s?.valueDeclaration &&
              ts.isVariableDeclaration(s.valueDeclaration) &&
              s.valueDeclaration.initializer
                ? evaluate(
                    s.valueDeclaration.initializer,
                    env,
                    route,
                    depth + 1,
                  )
                : empty()),
          );
        }
      }
      return { ...combine([...fields.values()]), fields };
    }
    if (ts.isArrayLiteralExpression(node)) {
      const items = node.elements.map((e) =>
        evaluate(e, env, route, depth + 1),
      );
      return { ...combine(items), items };
    }
    if (ts.isTemplateExpression(node)) {
      const values = node.templateSpans.map((s) =>
        evaluate(s.expression, env, route, depth + 1),
      );
      return {
        ...combine(values),
        text: values.every((v) => v.text !== undefined)
          ? node.head.text +
            node.templateSpans
              .map((s, i) => values[i]!.text + s.literal.text)
              .join("")
          : undefined,
      };
    }
    if (ts.isBinaryExpression(node)) {
      const right = evaluate(node.right, env, route, depth + 1);
      if (
        node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        ts.isIdentifier(node.left)
      ) {
        bind(node.left, right, env);
        return right;
      }
      if (
        node.operatorToken.kind === ts.SyntaxKind.PlusEqualsToken &&
        ts.isIdentifier(node.left)
      ) {
        const combined = combine([
          evaluate(node.left, env, route, depth + 1),
          right,
        ]);
        bind(node.left, combined, env);
        return combined;
      }
      if (
        node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
        node.operatorToken.kind <= ts.SyntaxKind.LastAssignment &&
        !ts.isIdentifier(node.left)
      ) {
        result.diagnostics.push({
          ...location(node),
          message:
            "Property/index mutation is not modeled; downstream constraints require manual review.",
        });
      }
      const left = evaluate(node.left, env, route, depth + 1);
      return {
        ...combine([left, right]),
        text:
          node.operatorToken.kind === ts.SyntaxKind.PlusToken &&
          left.text !== undefined &&
          right.text !== undefined
            ? left.text + right.text
            : undefined,
      };
    }
    if (ts.isConditionalExpression(node))
      return combine([
        evaluate(node.whenTrue, new Map(env), route, depth + 1),
        evaluate(node.whenFalse, new Map(env), route, depth + 1),
      ]);
    if (ts.isNewExpression(node)) {
      const callee = evaluate(node.expression, env, route, depth + 1);
      return { trace: [], driver: callee.driver };
    }
    if (ts.isTaggedTemplateExpression(node)) {
      const callee = evaluate(node.tag, env, route, depth + 1);
      // Tagged Prisma queries bind substitutions. Do not treat them as string interpolation.
      if (callee.driver === "prisma") {
        sinkCounts.add(`${location(node).file}:${node.pos}`);
        return empty();
      }
      return evaluate(node.template, env, route, depth + 1);
    }
    if (ts.isCallExpression(node)) {
      const callee = evaluate(node.expression, env, route, depth + 1);
      const args = node.arguments.map((a) =>
        evaluate(a, env, route, depth + 1),
      );
      if (ts.isPropertyAccessExpression(node.expression)) {
        const method = node.expression.name.text;
        const receiver = evaluate(
          node.expression.expression,
          env,
          route,
          depth + 1,
        );
        const sinkValue = inspectSink(node, method, receiver, args, route);
        if (
          ["json", "text", "get"].includes(method) &&
          receiver.origin?.startsWith("request")
        )
          return { trace: [evidence(node, "source", `request.${method}()`)] };
        if (sinkValue) return sinkValue;
      }
      if (callee.fn) return invoke(callee.fn, args, env, route, depth + 1);
      if (callee.driver) return { trace: [], driver: callee.driver };
      // Unknown helpers preserve taint, but do not certify authorization or sanitization.
      return combine(args);
    }
    return empty();
  }
  function inspectSink(
    node: ts.CallExpression,
    method: string,
    receiver: Value,
    args: Value[],
    route: string | undefined,
  ): Value | undefined {
    const loc = location(node);
    const key = `${loc.file}:${node.pos}:${route ?? ""}`;
    const driver = receiver.driver;
    if (!driver) return;
    const raw =
      (driver === "pg" && method === "query") ||
      (driver === "prisma" &&
        [
          "$queryRawUnsafe",
          "$executeRawUnsafe",
          "$queryRaw",
          "$executeRaw",
        ].includes(method)) ||
      (driver === "knex" && method === "raw");
    const orm = driver === "prisma" && operations.has(method);
    if (!raw && !orm) return;
    sinkCounts.add(`${loc.file}:${node.pos}`);
    const label = `${driver}.${method}`;
    const queryId = `query:${loc.file}:${loc.line}:${loc.column}`;
    if (!result.graph.nodes.some((n) => n.id === queryId))
      result.graph.nodes.push({ id: queryId, kind: "query", label });
    if (route)
      result.graph.edges.push({
        from: `route:${route}`,
        to: queryId,
        relation: "calls",
      });
    const sqlText =
      driver === "pg" && args[0]?.fields ? args[0].fields.get("text") : args[0];
    if (raw && sqlText?.trace.length) {
      emit(
        "REAPER-SQL-001",
        "User input reaches SQL text",
        "HIGH",
        "SQL Safety",
        89,
        sqlText,
        "Use driver-bound parameters for values; allowlist identifiers.",
        undefined,
        ["User-controlled input reaches the SQL text argument."],
      );
    }
    if (raw && sqlText?.text !== undefined) {
      const parsed = unrestrictedMutation(sqlText.text);
      if (parsed.unsupported)
        result.diagnostics.push({
          ...loc,
          message:
            "SQL syntax is outside the supported parser subset; query not classified.",
        });
      if (parsed.broad)
        emit(
          "REAPER-SQL-002",
          "Unrestricted SQL mutation",
          "MEDIUM",
          "SQL Safety",
          862,
          sqlText,
          "Verify that a whole-table mutation is intentional; add a bounded predicate otherwise.",
          undefined,
          [
            "A parsed UPDATE or DELETE statement has no WHERE predicate. This may be an intentional maintenance operation.",
          ],
        );
    }
    if (orm) {
      const receiverNode = ts.isPropertyAccessExpression(node.expression)
        ? node.expression.expression
        : undefined;
      const resource =
        receiverNode && ts.isPropertyAccessExpression(receiverNode)
          ? receiverNode.name.text
          : undefined;
      if (!resource) return;
      const metadata = config.resources?.[resource];
      const where = args[0]?.fields?.get("where") ?? empty();
      const resourceId = `resource:${resource}`;
      if (!result.graph.nodes.some((n) => n.id === resourceId))
        result.graph.nodes.push({
          id: resourceId,
          kind: "resource",
          label: resource,
        });
      result.graph.edges.push({
        from: queryId,
        to: resourceId,
        relation: "accesses",
      });
      function constrained(value: Value, fields: string[]): boolean {
        if (
          fields.some((field) => {
            const v = value.fields?.get(field);
            const principal =
              v?.principal ?? v?.fields?.get("equals")?.principal;
            return (
              !!principal &&
              (principal.split(".").at(-1) === field ||
                (metadata?.ownership?.includes(field) === true &&
                  ["id", "userId", "ownerId"].includes(
                    principal.split(".").at(-1)!,
                  )))
            );
          })
        )
          return true;
        const and = value.fields?.get("AND");
        if (and && (and.items ?? [and]).some((v) => constrained(v, fields)))
          return true;
        const or = value.fields?.get("OR");
        return (
          !!or?.items?.length && or.items.every((v) => constrained(v, fields))
        );
      }
      if (
        metadata?.ownership?.length &&
        where.trace.length &&
        !constrained(where, metadata.ownership)
      ) {
        const candidate = emit(
          "REAPER-AUTH-001",
          "Ownership constraint not established",
          "MEDIUM",
          "Authorization",
          639,
          where,
          "Constrain the query to a verified principal, or verify object authorization before returning data.",
          resource,
          [
            `Ownership relationship: ${metadata.ownership.join(", ")}`,
            "No supported principal constraint was found in this query. External authorization may exist.",
          ],
        );
        if (candidate) {
          const pending = pendingAuthorization.get(key) ?? {};
          pending.ownership = candidate;
          pendingAuthorization.set(key, pending);
        }
      }
      if (
        route &&
        metadata?.tenant?.length &&
        !constrained(where, metadata.tenant)
      ) {
        const candidate = emit(
          "REAPER-TENANT-001",
          "Tenant constraint not established",
          "MEDIUM",
          "Tenant Isolation",
          862,
          where,
          "Bind the tenant filter to a verified membership context. Do not trust a tenant supplied by the request.",
          resource,
          [
            `Tenant relationship: ${metadata.tenant.join(", ")}`,
            "No supported tenant constraint was found in this query. Database RLS is not inferred by source analysis.",
          ],
        );
        if (candidate) {
          const pending = pendingAuthorization.get(key) ?? {};
          pending.tenant = candidate;
          pendingAuthorization.set(key, pending);
        }
      }
      return { trace: [], resource, queryKey: key };
    }
    function emit(
      ruleId: string,
      title: string,
      severity: Finding["severity"],
      category: Finding["category"],
      cwe: number,
      value: Value,
      recommendation: string,
      resource: string | undefined,
      details: string[],
    ): Finding | undefined {
      if (visitedSinks.has(`${key}:${ruleId}`)) return undefined;
      visitedSinks.add(`${key}:${ruleId}`);
      const emitted = finding(
        {
          ...loc,
          ruleId,
          title,
          description: details.join(" "),
          severity,
          confidence: category === "SQL Safety" ? "HIGH" : "MEDIUM",
          category,
          cwe,
          route,
          resource,
          evidence: details,
          dataFlow: [...value.trace, evidence(node, "sink", label)],
          recommendation,
        },
        `${label}:${node.getText().replace(/\s+/g, " ")}`,
      );
      result.findings.push(emitted);
      return emitted;
    }
  }

  type GuardDimension = "ownership" | "tenant";
  interface GuardProof {
    queryKey: string;
    dimension: GuardDimension;
  }
  function principalMatches(
    principal: string,
    field: string,
    dimension: GuardDimension,
  ): boolean {
    const leaf = principal.split(".").at(-1);
    if (dimension === "ownership")
      return (
        leaf === field ||
        (["userId", "ownerId"].includes(field) &&
          ["id", "userId", "ownerId"].includes(leaf ?? ""))
      );
    return leaf === field;
  }
  function denialGuard(
    node: ts.Expression,
    env: Environment,
    route: string | undefined,
    depth: number,
  ): GuardProof[] {
    if (
      !ts.isBinaryExpression(node) ||
      ![
        ts.SyntaxKind.ExclamationEqualsToken,
        ts.SyntaxKind.ExclamationEqualsEqualsToken,
      ].includes(node.operatorToken.kind)
    )
      return [];
    const supportedOperand = (value: ts.Expression): boolean =>
      ts.isIdentifier(value) ||
      ts.isPropertyAccessExpression(value) ||
      ts.isElementAccessExpression(value);
    if (!supportedOperand(node.left) || !supportedOperand(node.right)) return [];
    const left = evaluate(node.left, env, route, depth + 1);
    const right = evaluate(node.right, env, route, depth + 1);
    function match(resourceValue: Value, principalValue: Value): GuardProof[] {
      if (
        !resourceValue.resource ||
        !resourceValue.resourceField ||
        !resourceValue.queryKey ||
        !principalValue.principal
      )
        return [];
      const metadata = config.resources?.[resourceValue.resource];
      const proofs: GuardProof[] = [];
      if (
        metadata?.ownership?.includes(resourceValue.resourceField) &&
        principalMatches(
          principalValue.principal,
          resourceValue.resourceField,
          "ownership",
        )
      )
        proofs.push({
          queryKey: resourceValue.queryKey,
          dimension: "ownership",
        });
      if (
        metadata?.tenant?.includes(resourceValue.resourceField) &&
        principalMatches(
          principalValue.principal,
          resourceValue.resourceField,
          "tenant",
        )
      )
        proofs.push({
          queryKey: resourceValue.queryKey,
          dimension: "tenant",
        });
      return proofs;
    }
    return [...match(left, right), ...match(right, left)];
  }
  function endsInThrow(node: ts.Statement): boolean {
    if (ts.isThrowStatement(node)) return true;
    if (!ts.isBlock(node) || node.statements.length === 0) return false;
    return endsInThrow(node.statements[node.statements.length - 1]!);
  }
  function applyGuardProofs(proofs: GuardProof[]): void {
    for (const proof of proofs) {
      const pending = pendingAuthorization.get(proof.queryKey);
      const candidate = pending?.[proof.dimension];
      if (!candidate) continue;
      result.findings = result.findings.filter(
        (item) => item.id !== candidate.id,
      );
      if (pending) delete pending[proof.dimension];
    }
  }

  function statement(
    node: ts.Statement,
    env: Environment,
    route: string | undefined,
    depth: number,
  ): { returned: boolean; value: Value } {
    if (ts.isVariableStatement(node))
      for (const declaration of node.declarationList.declarations)
        if (declaration.initializer) {
          const value = evaluate(declaration.initializer, env, route, depth);
          if (value.trace.length)
            value.trace = [
              ...value.trace,
              evidence(
                declaration,
                "propagation",
                `assignment to ${declaration.name.getText()}`,
              ),
            ];
          bind(declaration.name, value, env);
        }
    if (ts.isExpressionStatement(node))
      evaluate(node.expression, env, route, depth);
    if (ts.isReturnStatement(node))
      return {
        returned: true,
        value: node.expression
          ? evaluate(node.expression, env, route, depth)
          : empty(),
      };
    if (ts.isThrowStatement(node)) return { returned: true, value: empty() };
    if (ts.isBlock(node)) return block(node, env, route, depth);
    if (ts.isIfStatement(node)) {
      evaluate(node.expression, env, route, depth);
      const guardProofs = denialGuard(node.expression, env, route, depth);
      const yes = new Map(env),
        no = new Map(env);
      const a = statement(node.thenStatement, yes, route, depth);
      const b = node.elseStatement
        ? statement(node.elseStatement, no, route, depth)
        : { returned: false, value: empty() };
      if (!node.elseStatement && endsInThrow(node.thenStatement))
        applyGuardProofs(guardProofs);
      for (const s of new Set([...yes.keys(), ...no.keys()])) {
        const y = yes.get(s) ?? empty(),
          n = no.get(s) ?? empty();
        if (a.returned && !b.returned) env.set(s, n);
        else if (b.returned && !a.returned) env.set(s, y);
        else env.set(s, y === n ? y : combine([y, n]));
      }
      return {
        returned: a.returned && b.returned,
        value: combine([a.value, b.value]),
      };
    }
    if (
      ts.isForStatement(node) ||
      ts.isForOfStatement(node) ||
      ts.isForInStatement(node) ||
      ts.isWhileStatement(node) ||
      ts.isDoStatement(node) ||
      ts.isTryStatement(node) ||
      ts.isSwitchStatement(node)
    ) {
      result.diagnostics.push({
        ...location(node),
        message:
          "Loop, try or switch control flow is unsupported; review this region manually.",
      });
    }
    return { returned: false, value: empty() };
  }
  function block(
    node: ts.Block,
    env: Environment,
    route: string | undefined,
    depth: number,
  ): { returned: boolean; value: Value } {
    const returns: Value[] = [];
    for (const child of node.statements) {
      const step = statement(child, env, route, depth);
      returns.push(step.value);
      if (step.returned) return { returned: true, value: combine(returns) };
    }
    return { returned: false, value: combine(returns) };
  }
  const active = new Set<Fn>();
  function invoke(
    fn: Fn,
    args: Value[],
    outer: Environment,
    route: string | undefined,
    depth: number,
  ): Value {
    if (active.has(fn) || depth > 40) {
      result.diagnostics.push({
        ...location(fn),
        message: "Recursive/deep call not expanded.",
      });
      return combine(args);
    }
    active.add(fn);
    try {
      const env = new Map(outer);
      fn.parameters.forEach((p, i) => bind(p.name, args[i] ?? empty(), env));
      if (!fn.body) return empty();
      return ts.isBlock(fn.body)
        ? block(fn.body, env, route, depth).value
        : evaluate(fn.body, env, route, depth);
    } finally {
      active.delete(fn);
    }
  }
  const routes = new Set<Fn>();
  function addRoute(fn: Fn, route: string, next: boolean): void {
    routes.add(fn);
    result.metrics.routes++;
    result.graph.nodes.push({
      id: `route:${route}`,
      kind: "route",
      label: route,
    });
    const first = fn.parameters[0]?.name;
    const origin = first && ts.isIdentifier(first) ? first.text : "request";
    // Express and Fastify request aliases are normalized to req/request.
    const request: Value = {
      trace: [],
      origin: next ? "request" : origin === "request" ? "request" : "req",
    };
    const context: Value = next
      ? {
          trace: [],
          fields: new Map([
            [
              "params",
              {
                origin: "request.params",
                trace: [evidence(fn, "source", "Next.js route params")],
              },
            ],
          ]),
        }
      : empty();
    invoke(fn, [request, context], new Map(), route, 0);
  }
  for (const sf of program.getSourceFiles()) {
    if (!allowed.has(sf.fileName)) continue;
    for (const diagnostic of program.getSyntacticDiagnostics(sf))
      result.diagnostics.push({
        file: path.relative(root, sf.fileName),
        message: ts.flattenDiagnosticMessageText(diagnostic.messageText, " "),
      });
    function visit(node: ts.Node): void {
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        ["get", "post", "put", "patch", "delete", "all"].includes(
          node.expression.name.text,
        ) &&
        node.arguments[0] &&
        ts.isStringLiteral(node.arguments[0])
      ) {
        // Only recognize route registration when its receiver resolves to an Express/Fastify import.
        const receiver = node.expression.expression;
        const routeLibrary = library(receiver, new Set());
        if (routeLibrary === "express" || routeLibrary === "fastify") {
          const last = node.arguments[node.arguments.length - 1];
          const fn = last
            ? evaluate(last, new Map(), undefined, 0).fn
            : undefined;
          if (fn)
            addRoute(
              fn,
              `${node.expression.name.text.toUpperCase()} ${node.arguments[0].text}`,
              false,
            );
        }
      }
      if (
        ts.isFunctionDeclaration(node) &&
        node.name &&
        ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"].includes(
          node.name.text,
        ) &&
        node.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword) &&
        /(?:^|[/\\])route\.[cm]?[jt]sx?$/.test(sf.fileName)
      )
        addRoute(
          node,
          `${node.name.text} ${path.relative(root, sf.fileName)}`,
          true,
        );
      ts.forEachChild(node, visit);
    }
    visit(sf);
    // Analyze standalone functions as unbound: constants are inspectable, arbitrary parameters are not assumed to be HTTP input.
    for (const node of sf.statements) {
      if (ts.isFunctionDeclaration(node) && !routes.has(node))
        invoke(node, [], new Map(), undefined, 0);
      else if (ts.isVariableStatement(node) || ts.isExpressionStatement(node))
        statement(node, new Map(), undefined, 0);
    }
  }
  function library(
    node: ts.Expression,
    seen: Set<ts.Symbol>,
  ): string | undefined {
    if (ts.isCallExpression(node) || ts.isNewExpression(node))
      return library(node.expression, seen);
    if (ts.isPropertyAccessExpression(node))
      return library(node.expression, seen);
    const raw = symbol(node);
    if (!raw || seen.has(raw)) return undefined;
    seen.add(raw);
    for (const declaration of raw.declarations ?? []) {
      let parent: ts.Node | undefined = declaration;
      while (parent && !ts.isImportDeclaration(parent)) parent = parent.parent;
      if (parent && ts.isStringLiteral(parent.moduleSpecifier))
        return parent.moduleSpecifier.text;
    }
    for (const declaration of canonical(raw).declarations ?? [])
      if (ts.isVariableDeclaration(declaration) && declaration.initializer)
        return library(declaration.initializer, seen);
    return undefined;
  }
  result.metrics.sinks = sinkCounts.size;
  result.graph.edges = [
    ...new Map(result.graph.edges.map((e) => [JSON.stringify(e), e])).values(),
  ];
}
