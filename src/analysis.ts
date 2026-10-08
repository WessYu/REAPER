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
  boundArgs?: Value[];
  resource?: string;
  resourceField?: string;
  queryKey?: string;
  operation?: string;
}
type Environment = Map<ts.Symbol, Value>;
const empty = (): Value => ({ trace: [] });
const drivers = new Map([
  ["@prisma/client", "prisma"],
  ["pg", "pg"],
  ["knex", "knex"],
  ["@supabase/supabase-js", "supabase"],
  ["drizzle-orm/node-postgres", "drizzle"],
  ["drizzle-orm/postgres-js", "drizzle"],
  ["drizzle-orm/neon-http", "drizzle"],
]);
const supabaseOperations = new Set([
  "select",
  "insert",
  "update",
  "upsert",
  "delete",
]);
const supabaseStorageOperations = new Set([
  "download",
  "upload",
  "update",
  "remove",
  "list",
  "move",
  "copy",
  "createSignedUrl",
  "createSignedUrls",
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
  const scripts = files.filter(
    (f) => !f.endsWith(".prisma") && !f.endsWith(".sql"),
  );
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

  function importedName(node: ts.Expression): string | undefined {
    const raw = symbol(node);
    if (!raw) return undefined;
    for (const declaration of raw.declarations ?? []) {
      if (ts.isImportSpecifier(declaration))
        return (declaration.propertyName ?? declaration.name).text;
      if (ts.isImportClause(declaration) && declaration.name)
        return declaration.name.text;
    }
    return undefined;
  }

  function importedModule(node: ts.Expression): string | undefined {
    const raw = symbol(node);
    if (!raw) return undefined;
    for (const declaration of raw.declarations ?? []) {
      let current: ts.Node | undefined = declaration;
      while (current && !ts.isImportDeclaration(current))
        current = current.parent;
      if (current && ts.isStringLiteral(current.moduleSpecifier))
        return current.moduleSpecifier.text;
    }
    return undefined;
  }

  function environmentName(node: ts.Expression): string | undefined {
    if (
      !ts.isPropertyAccessExpression(node) ||
      !ts.isPropertyAccessExpression(node.expression) ||
      node.expression.name.text !== "env"
    )
      return undefined;
    const root = node.expression.expression;
    if (ts.isIdentifier(root) && root.text === "process") return node.name.text;
    if (
      ts.isMetaProperty(root) &&
      root.keywordToken === ts.SyntaxKind.ImportKeyword &&
      root.name.text === "meta"
    )
      return node.name.text;
    return undefined;
  }

  interface CredentialDescriptor {
    kind: "env" | "hardcoded-service-role";
    name?: string;
  }

  function credentialDescriptor(
    node: ts.Expression,
    seen = new Set<ts.Symbol>(),
  ): CredentialDescriptor | undefined {
    if (
      ts.isParenthesizedExpression(node) ||
      ts.isAsExpression(node) ||
      ts.isNonNullExpression(node) ||
      ts.isSatisfiesExpression(node)
    )
      return credentialDescriptor(node.expression, seen);
    const env = environmentName(node);
    if (env) return { kind: "env", name: env };
    if (ts.isStringLiteralLike(node)) {
      if (node.text.startsWith("sb_secret_"))
        return { kind: "hardcoded-service-role" };
      const parts = node.text.split(".");
      if (parts.length === 3 && parts[1]) {
        try {
          const payload = JSON.parse(
            Buffer.from(parts[1], "base64url").toString("utf8"),
          ) as { role?: unknown };
          if (payload.role === "service_role")
            return { kind: "hardcoded-service-role" };
        } catch {
          return undefined;
        }
      }
      return undefined;
    }
    if (ts.isIdentifier(node)) {
      const raw = symbol(node);
      if (!raw) return undefined;
      const resolved = canonical(raw);
      if (seen.has(resolved)) return undefined;
      seen.add(resolved);
      for (const declaration of resolved.declarations ?? [])
        if (ts.isVariableDeclaration(declaration) && declaration.initializer)
          return credentialDescriptor(declaration.initializer, seen);
    }
    return undefined;
  }

  function isClientSource(node: ts.Node): boolean {
    for (const statement of node.getSourceFile().statements) {
      if (
        !ts.isExpressionStatement(statement) ||
        !ts.isStringLiteral(statement.expression)
      )
        break;
      if (statement.expression.text === "use client") return true;
    }
    return false;
  }

  function inspectSupabaseClient(
    node: ts.CallExpression,
    route?: string,
  ): void {
    const credential = node.arguments[1]
      ? credentialDescriptor(node.arguments[1])
      : undefined;
    if (!credential) return;
    const envName = credential.name;
    const serviceRoleEnv =
      credential.kind === "env" &&
      !!envName &&
      /(?:^|_)SERVICE_?ROLE(?:_|$)/i.test(envName);
    const publicEnv =
      credential.kind === "env" &&
      !!envName &&
      /^(?:NEXT_PUBLIC_|VITE_|PUBLIC_)/.test(envName);
    const hardcoded = credential.kind === "hardcoded-service-role";
    const clientContext = isClientSource(node);
    if (!hardcoded && !(serviceRoleEnv && (publicEnv || clientContext))) return;

    const loc = location(node);
    const visitKey = `${loc.file}:${node.pos}:REAPER-SUPA-001`;
    if (visitedSinks.has(visitKey)) return;
    visitedSinks.add(visitKey);
    const sourceLabel = hardcoded
      ? "hardcoded Supabase service-role credential"
      : `Supabase service-role environment reference: ${envName}`;
    result.findings.push(
      finding(
        {
          ...loc,
          ruleId: "REAPER-SUPA-001",
          title:
            "Supabase service-role credential exposed to source/client context",
          description: hardcoded
            ? "A credential with service_role semantics is embedded directly in source."
            : "A service-role credential is referenced from client-exposed configuration.",
          severity: "HIGH",
          confidence: "HIGH",
          category: "Supabase",
          cwe: 798,
          route,
          evidence: [
            hardcoded
              ? "Service-role semantics were identified without retaining the credential value."
              : `Environment variable ${envName} indicates a service-role credential in a client-exposed context.`,
          ],
          dataFlow: [
            evidence(node.arguments[1]!, "source", sourceLabel),
            evidence(node, "sink", "supabase.createClient"),
          ],
          recommendation:
            "Keep service-role credentials server-only, load them from non-public secret storage, and use an anon/publishable key in browser code with reviewed RLS policies.",
        },
        `supabase:createClient:${hardcoded ? "hardcoded-service-role" : envName}`,
      ),
    );
  }

  function importDriver(s: ts.Symbol): string | undefined {
    for (const declaration of s.declarations ?? []) {
      let node: ts.Node | undefined = declaration;
      while (node && !ts.isImportDeclaration(node)) node = node.parent;
      if (node && ts.isStringLiteral(node.moduleSpecifier)) {
        if (
          node.moduleSpecifier.text === "drizzle-orm" &&
          ts.isImportSpecifier(declaration) &&
          (declaration.propertyName ?? declaration.name).text === "sql"
        )
          return "drizzle-sql";
        return drivers.get(node.moduleSpecifier.text);
      }
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
    let value: Value;
    if (origin && principals.has(origin))
      value = { trace: [], principal: origin, origin };
    else {
      const source =
        origin &&
        /^(?:req|request)\.(?:params|query|body|headers|cookies)(?:\.|$)/.test(
          origin,
        );
      if (source) value = { origin, trace: [evidence(node, "source", origin)] };
      else
        value = {
          ...base,
          fields: undefined,
          origin,
          resourceField: base.resource ? key : base.resourceField,
          text: base.text === undefined ? undefined : `${base.text}.${key}`,
          operation:
            base.driver === "supabase" && key === "storage"
              ? "storage"
              : base.operation,
        };
    }
    base.fields ??= new Map<string, Value>();
    base.fields.set(key, value);
    return value;
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
        value.resource ||
        value.queryKey ||
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
        if (ts.isMethodDeclaration(property)) {
          const key = propertyKey(property.name);
          if (key) fields.set(key, { trace: [], fn: property });
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
        node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        (ts.isPropertyAccessExpression(node.left) ||
          ts.isElementAccessExpression(node.left))
      ) {
        const base = evaluate(node.left.expression, env, route, depth + 1);
        const key = ts.isPropertyAccessExpression(node.left)
          ? node.left.name.text
          : evaluate(node.left.argumentExpression, env, route, depth + 1).text;
        if (key !== undefined) {
          base.fields ??= new Map<string, Value>();
          base.fields.set(key, right);
          return right;
        }
      }
      if (
        node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
        node.operatorToken.kind <= ts.SyntaxKind.LastAssignment &&
        !ts.isIdentifier(node.left) &&
        !ts.isPropertyAccessExpression(node.left) &&
        !ts.isElementAccessExpression(node.left)
      ) {
        result.diagnostics.push({
          ...location(node),
          message:
            "Complex assignment target is not modeled; downstream constraints require manual review.",
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
      const moduleName = importedModule(node.expression);
      const importName = importedName(node.expression);

      if (
        ts.isPropertyAccessExpression(node.expression) &&
        ts.isIdentifier(node.expression.expression)
      ) {
        const owner = node.expression.expression.text;
        const method = node.expression.name.text;
        if (owner === "Object" && method === "assign" && args[0]) {
          const target = args[0];
          target.fields ??= new Map<string, Value>();
          for (const source of args.slice(1))
            for (const [key, value] of source.fields ?? [])
              target.fields.set(key, value);
          target.trace = combine(args).trace;
          return target;
        }
        if (
          owner === "Object" &&
          method === "defineProperty" &&
          args[0] &&
          args[1]?.text !== undefined
        ) {
          const descriptor = args[2]?.fields?.get("value");
          if (descriptor) {
            args[0].fields ??= new Map<string, Value>();
            args[0].fields.set(args[1].text, descriptor);
          }
          return args[0];
        }
        if (
          owner === "Reflect" &&
          method === "get" &&
          args[0] &&
          args[1]?.text !== undefined
        )
          return member(args[0], args[1].text, node);
        if (
          owner === "Reflect" &&
          method === "set" &&
          args[0] &&
          args[1]?.text !== undefined &&
          args[2]
        ) {
          args[0].fields ??= new Map<string, Value>();
          args[0].fields.set(args[1].text, args[2]);
          return args[2];
        }
      }
      if (
        moduleName?.startsWith("drizzle-orm/") &&
        ["pgTable", "mysqlTable", "sqliteTable"].includes(importName ?? "") &&
        args[0]?.text
      )
        return { trace: [], resource: args[0].text };
      if (moduleName === "drizzle-orm" && importName === "eq") {
        const left = args[0] ?? empty();
        const right = args[1] ?? empty();
        const field = left.resourceField ?? right.resourceField;
        const value = left.resourceField ? right : left;
        return field
          ? {
              ...combine(args),
              fields: new Map([[field, value]]),
            }
          : combine(args);
      }
      if (moduleName === "drizzle-orm" && importName === "and") {
        const fields = new Map<string, Value>();
        for (const arg of args)
          for (const [key, value] of arg.fields ?? []) fields.set(key, value);
        return { ...combine(args), fields };
      }
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
        if (method === "bind" && receiver.fn)
          return {
            ...receiver,
            boundArgs: [...(receiver.boundArgs ?? []), ...args.slice(1)],
          };
        if (method === "call" && receiver.fn)
          return invoke(
            receiver.fn,
            [...(receiver.boundArgs ?? []), ...args.slice(1)],
            env,
            route,
            depth + 1,
          );
        if (method === "apply" && receiver.fn)
          return invoke(
            receiver.fn,
            [...(receiver.boundArgs ?? []), ...(args[1]?.items ?? [])],
            env,
            route,
            depth + 1,
          );
        if (method === "push" && receiver.items) {
          receiver.items.push(...args);
          return receiver;
        }
      }
      if (callee.fn)
        return invoke(
          callee.fn,
          [...(callee.boundArgs ?? []), ...args],
          env,
          route,
          depth + 1,
        );
      if (callee.driver === "knex" && args[0]?.text)
        return {
          trace: combine(args).trace,
          driver: "knex",
          resource: args[0].text,
        };
      if (callee.driver) {
        if (
          callee.driver === "supabase" &&
          importedName(node.expression) === "createClient"
        )
          inspectSupabaseClient(node, route);
        return { trace: [], driver: callee.driver };
      }
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

    if (driver === "drizzle") {
      if (method === "select")
        return { ...receiver, trace: combine(args).trace, operation: method };
      if (
        ["insert", "update", "delete"].includes(method) &&
        args[0]?.resource
      ) {
        const resource = args[0].resource;
        const queryId = `query:${loc.file}:${loc.line}:${loc.column}`;
        sinkCounts.add(`${loc.file}:${node.pos}`);
        if (!result.graph.nodes.some((n) => n.id === queryId))
          result.graph.nodes.push({
            id: queryId,
            kind: "query",
            label: `drizzle.${method}`,
          });
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
        if (route)
          result.graph.edges.push({
            from: `route:${route}`,
            to: queryId,
            relation: "calls",
          });
        return {
          ...receiver,
          trace: combine([receiver, ...args]).trace,
          resource,
          operation: method,
        };
      }
      if (
        method === "from" &&
        receiver.operation === "select" &&
        args[0]?.resource
      ) {
        const resource = args[0].resource;
        const queryId = `query:${loc.file}:${loc.line}:${loc.column}`;
        sinkCounts.add(`${loc.file}:${node.pos}`);
        if (!result.graph.nodes.some((n) => n.id === queryId))
          result.graph.nodes.push({
            id: queryId,
            kind: "query",
            label: "drizzle.select",
          });
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
        if (route)
          result.graph.edges.push({
            from: `route:${route}`,
            to: queryId,
            relation: "calls",
          });
        return {
          ...receiver,
          trace: combine([receiver, ...args]).trace,
          resource,
        };
      }
      if (receiver.resource || receiver.operation)
        return {
          ...receiver,
          trace: combine([receiver, ...args]).trace,
          fields:
            method === "where" && args[0]?.fields
              ? args[0].fields
              : receiver.fields,
        };
      return undefined;
    }

    if (driver === "knex" && receiver.resource && method !== "raw") {
      if (["select", "insert", "update", "delete", "del"].includes(method)) {
        const resource = receiver.resource;
        const queryId = `query:${loc.file}:${loc.line}:${loc.column}`;
        sinkCounts.add(`${loc.file}:${node.pos}`);
        if (!result.graph.nodes.some((n) => n.id === queryId))
          result.graph.nodes.push({
            id: queryId,
            kind: "query",
            label: `knex.${method}`,
          });
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
        if (route)
          result.graph.edges.push({
            from: `route:${route}`,
            to: queryId,
            relation: "calls",
          });
      }
      return {
        ...receiver,
        trace: combine([receiver, ...args]).trace,
        operation: ["select", "insert", "update", "delete", "del"].includes(
          method,
        )
          ? method
          : receiver.operation,
      };
    }

    if (driver === "supabase") {
      if (
        method === "from" &&
        receiver.operation === "storage" &&
        args[0]?.text
      ) {
        return {
          trace: combine(args).trace,
          driver,
          operation: "storage-bucket",
          resource: `storage:${args[0].text}`,
        };
      }
      if (method === "from" && args[0]?.text) {
        return {
          trace: combine(args).trace,
          driver,
          resource: args[0].text,
        };
      }
      if (method === "rpc" && args[0]?.text) {
        const resource = `rpc:${args[0].text}`;
        const queryId = `query:${loc.file}:${loc.line}:${loc.column}`;
        sinkCounts.add(`${loc.file}:${node.pos}`);
        if (!result.graph.nodes.some((n) => n.id === queryId))
          result.graph.nodes.push({
            id: queryId,
            kind: "query",
            label: "supabase.rpc",
          });
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
        if (route)
          result.graph.edges.push({
            from: `route:${route}`,
            to: queryId,
            relation: "calls",
          });
        return { trace: combine(args).trace, driver, resource };
      }
      if (
        receiver.resource?.startsWith("storage:") &&
        supabaseStorageOperations.has(method)
      ) {
        const resource = receiver.resource;
        const queryId = `query:${loc.file}:${loc.line}:${loc.column}`;
        sinkCounts.add(`${loc.file}:${node.pos}`);
        if (!result.graph.nodes.some((n) => n.id === queryId))
          result.graph.nodes.push({
            id: queryId,
            kind: "query",
            label: `supabase.storage.${method}`,
          });
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
        if (route)
          result.graph.edges.push({
            from: `route:${route}`,
            to: queryId,
            relation: "calls",
          });
        return {
          ...receiver,
          trace: combine([receiver, ...args]).trace,
          driver,
          operation: method,
        };
      }
      if (receiver.resource && supabaseOperations.has(method)) {
        const resource = receiver.resource;
        const queryId = `query:${loc.file}:${loc.line}:${loc.column}`;
        sinkCounts.add(`${loc.file}:${node.pos}`);
        if (!result.graph.nodes.some((n) => n.id === queryId))
          result.graph.nodes.push({
            id: queryId,
            kind: "query",
            label: `supabase.${method}`,
          });
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
        if (route)
          result.graph.edges.push({
            from: `route:${route}`,
            to: queryId,
            relation: "calls",
          });
        return {
          ...receiver,
          trace: combine([receiver, ...args]).trace,
          driver,
        };
      }
      if (receiver.resource)
        return {
          ...receiver,
          trace: combine([receiver, ...args]).trace,
          driver,
        };
      return undefined;
    }

    const raw =
      (driver === "pg" && method === "query") ||
      (driver === "prisma" &&
        [
          "$queryRawUnsafe",
          "$executeRawUnsafe",
          "$queryRaw",
          "$executeRaw",
        ].includes(method)) ||
      (driver === "knex" && method === "raw") ||
      (driver === "drizzle-sql" && method === "raw");
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
          metadata.sensitive?.length ? "HIGH" : "MEDIUM",
          "Authorization",
          639,
          where,
          "Constrain the query to a verified principal, or verify object authorization before returning data.",
          resource,
          [
            `Ownership relationship: ${metadata.ownership.join(", ")}`,
            ...(metadata.sensitive?.length
              ? [
                  `Sensitive fields on resource: ${metadata.sensitive.join(", ")}`,
                ]
              : []),
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
          metadata.sensitive?.length ? "HIGH" : "MEDIUM",
          "Tenant Isolation",
          862,
          where,
          "Bind the tenant filter to a verified membership context. Do not trust a tenant supplied by the request.",
          resource,
          [
            `Tenant relationship: ${metadata.tenant.join(", ")}`,
            ...(metadata.sensitive?.length
              ? [
                  `Sensitive fields on resource: ${metadata.sensitive.join(", ")}`,
                ]
              : []),
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
    if (!supportedOperand(node.left) || !supportedOperand(node.right))
      return [];
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

  function mergeEnvironment(
    target: Environment,
    ...branches: Environment[]
  ): void {
    for (const s of new Set(branches.flatMap((branch) => [...branch.keys()]))) {
      const values = branches.map((branch) => branch.get(s) ?? empty());
      const first = values[0];
      target.set(
        s,
        first && values.every((value) => value === first)
          ? first
          : combine(values),
      );
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
    if (ts.isForStatement(node)) {
      const loop = new Map(env);
      if (node.initializer) {
        if (ts.isVariableDeclarationList(node.initializer)) {
          for (const declaration of node.initializer.declarations)
            if (declaration.initializer)
              bind(
                declaration.name,
                evaluate(declaration.initializer, loop, route, depth + 1),
                loop,
              );
        } else evaluate(node.initializer, loop, route, depth + 1);
      }
      if (node.condition) evaluate(node.condition, loop, route, depth + 1);
      statement(node.statement, loop, route, depth + 1);
      if (node.incrementor) evaluate(node.incrementor, loop, route, depth + 1);
      mergeEnvironment(env, loop);
      return { returned: false, value: empty() };
    }
    if (ts.isForOfStatement(node) || ts.isForInStatement(node)) {
      const loop = new Map(env);
      const iterable = evaluate(node.expression, loop, route, depth + 1);
      const value =
        ts.isForOfStatement(node) && iterable.items?.length
          ? combine(iterable.items)
          : iterable;
      if (ts.isVariableDeclarationList(node.initializer)) {
        const declaration = node.initializer.declarations[0];
        if (declaration) bind(declaration.name, value, loop);
      } else if (ts.isIdentifier(node.initializer))
        bind(node.initializer, value, loop);
      statement(node.statement, loop, route, depth + 1);
      mergeEnvironment(env, loop);
      return { returned: false, value: empty() };
    }
    if (ts.isWhileStatement(node) || ts.isDoStatement(node)) {
      const loop = new Map(env);
      evaluate(node.expression, loop, route, depth + 1);
      statement(node.statement, loop, route, depth + 1);
      mergeEnvironment(env, loop);
      return { returned: false, value: empty() };
    }
    if (ts.isTryStatement(node)) {
      const success = new Map(env);
      const failure = new Map(env);
      const a = block(node.tryBlock, success, route, depth + 1);
      let b = { returned: false, value: empty() };
      if (node.catchClause) {
        if (node.catchClause.variableDeclaration)
          bind(node.catchClause.variableDeclaration.name, empty(), failure);
        b = block(node.catchClause.block, failure, route, depth + 1);
      }
      mergeEnvironment(env, success, failure);
      if (node.finallyBlock) {
        const final = block(node.finallyBlock, env, route, depth + 1);
        if (final.returned) return final;
      }
      return {
        returned: a.returned && !!node.catchClause && b.returned,
        value: combine([a.value, b.value]),
      };
    }
    if (ts.isSwitchStatement(node)) {
      evaluate(node.expression, env, route, depth + 1);
      const branches: Environment[] = [];
      const values: Value[] = [];
      for (const clause of node.caseBlock.clauses) {
        const branch = new Map(env);
        if (ts.isCaseClause(clause))
          evaluate(clause.expression, branch, route, depth + 1);
        let value = empty();
        for (const child of clause.statements) {
          if (ts.isBreakStatement(child)) break;
          const step = statement(child, branch, route, depth + 1);
          value = combine([value, step.value]);
          if (step.returned) break;
        }
        branches.push(branch);
        values.push(value);
      }
      mergeEnvironment(env, ...branches);
      return { returned: false, value: combine(values) };
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
      if (step.returned) return { returned: true, value: step.value };
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
  type MiddlewareStep = { fn: Fn } | { contract: string };
  const routeMiddleware = new Map<string, MiddlewareStep[]>();
  const inheritedMiddleware: Array<{
    prefix?: string;
    step: MiddlewareStep;
  }> = [];
  function middlewareContract(node: ts.Expression): string | undefined {
    const candidates = new Set<string>([node.getText()]);
    if (ts.isIdentifier(node)) candidates.add(node.text);
    if (ts.isPropertyAccessExpression(node)) candidates.add(node.name.text);
    const imported = importedName(node);
    if (imported) candidates.add(imported);
    return [...candidates].find((name) => config.middleware?.[name]);
  }
  function addMiddleware(step: MiddlewareStep, route: string): void {
    const list = routeMiddleware.get(route) ?? [];
    if (
      !list.some((candidate) =>
        "fn" in step && "fn" in candidate
          ? candidate.fn === step.fn
          : "contract" in step &&
            "contract" in candidate &&
            candidate.contract === step.contract,
      )
    )
      list.push(step);
    routeMiddleware.set(route, list);
  }
  function establishPrincipal(request: Value, principal: string): void {
    const parts = principal.split(".");
    if (!["req", "request"].includes(parts[0] ?? "")) return;
    let current = request;
    let origin = parts[0] === "request" ? "request" : "req";
    for (const part of parts.slice(1, -1)) {
      origin += `.${part}`;
      current.fields ??= new Map<string, Value>();
      let next = current.fields.get(part);
      if (!next) {
        next = { trace: [], origin, fields: new Map<string, Value>() };
        current.fields.set(part, next);
      }
      current = next;
    }
    const leaf = parts.at(-1);
    if (!leaf) return;
    const normalized =
      parts[0] === "request" ? principal : `req.${parts.slice(1).join(".")}`;
    current.fields ??= new Map<string, Value>();
    current.fields.set(leaf, {
      trace: [],
      origin: normalized,
      principal: normalized,
    });
  }
  function runMiddleware(
    step: MiddlewareStep,
    request: Value,
    env: Environment,
    route: string,
  ): void {
    if ("fn" in step) {
      invoke(step.fn, [request, empty(), empty()], env, route, 0);
      return;
    }
    for (const principal of config.middleware?.[step.contract]?.establishes ??
      [])
      establishPrincipal(request, principal);
  }
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
    const env = new Map<ts.Symbol, Value>();
    const routePath = route.includes(" ")
      ? route.slice(route.indexOf(" ") + 1)
      : route;
    for (const middleware of inheritedMiddleware)
      if (
        middleware.prefix === undefined ||
        routePath === middleware.prefix ||
        routePath.startsWith(
          middleware.prefix.endsWith("/")
            ? middleware.prefix
            : middleware.prefix + "/",
        )
      )
        runMiddleware(middleware.step, request, env, route);
    for (const middleware of routeMiddleware.get(route) ?? [])
      runMiddleware(middleware, request, env, route);
    invoke(fn, [request, context], env, route, 0);
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
        ts.isPropertyAccessExpression(node.expression)
      ) {
        const method = node.expression.name.text;
        const receiver = node.expression.expression;
        const routeLibrary = library(receiver, new Set());
        if (
          routeLibrary === "express" &&
          method === "use" &&
          node.arguments.length
        ) {
          const first = node.arguments[0];
          const prefix =
            first && ts.isStringLiteral(first) ? first.text : undefined;
          const start = prefix === undefined ? 0 : 1;
          for (const argument of node.arguments.slice(start)) {
            const fn = evaluate(argument, new Map(), undefined, 0).fn;
            const contract = middlewareContract(argument);
            if (fn) inheritedMiddleware.push({ prefix, step: { fn } });
            else if (contract)
              inheritedMiddleware.push({
                prefix,
                step: { contract },
              });
          }
        }
        if (
          routeLibrary === "fastify" &&
          method === "addHook" &&
          node.arguments[0] &&
          ts.isStringLiteral(node.arguments[0]) &&
          ["onRequest", "preParsing", "preValidation", "preHandler"].includes(
            node.arguments[0].text,
          )
        ) {
          const hook = node.arguments[1];
          const fn = hook
            ? evaluate(hook, new Map(), undefined, 0).fn
            : undefined;
          const contract = hook ? middlewareContract(hook) : undefined;
          if (fn) inheritedMiddleware.push({ step: { fn } });
          else if (contract) inheritedMiddleware.push({ step: { contract } });
        }
      }
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
          const route = `${node.expression.name.text.toUpperCase()} ${node.arguments[0].text}`;
          const handlerArguments = node.arguments.slice(1);
          const handlerValues = handlerArguments.map((argument) => ({
            fn: evaluate(argument, new Map(), route, 0).fn,
            contract: middlewareContract(argument),
          }));
          const final = handlerValues.at(-1)?.fn;
          if (final) {
            for (const middleware of handlerValues.slice(0, -1)) {
              if (middleware.fn) addMiddleware({ fn: middleware.fn }, route);
              else if (middleware.contract)
                addMiddleware({ contract: middleware.contract }, route);
            }
            addRoute(final, route, false);
          }
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
