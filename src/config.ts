import ts from "typescript";
import { readFile } from "node:fs/promises";
import type { Config } from "./model.js";
// Parse a literal export; never import or execute a scanned project's configuration.
export async function readConfig(file: string): Promise<Config> {
  const source = ts.createSourceFile(
    file,
    await readFile(file, "utf8"),
    ts.ScriptTarget.Latest,
    true,
  );
  const exports = source.statements.filter(ts.isExportAssignment);
  if (exports.length !== 1 || !exports[0])
    throw new Error("Config must contain one export default object.");
  function literal(node: ts.Expression): unknown {
    if (ts.isAsExpression(node) || ts.isSatisfiesExpression(node))
      return literal(node.expression);
    if (ts.isStringLiteral(node)) return node.text;
    if (ts.isNumericLiteral(node)) return Number(node.text);
    if (node.kind === ts.SyntaxKind.TrueKeyword) return true;
    if (node.kind === ts.SyntaxKind.FalseKeyword) return false;
    if (node.kind === ts.SyntaxKind.NullKeyword) return null;
    if (ts.isArrayLiteralExpression(node))
      return node.elements.map((e) => literal(e));
    if (ts.isObjectLiteralExpression(node)) {
      const result: Record<string, unknown> = Object.create(null) as Record<
        string,
        unknown
      >;
      for (const property of node.properties) {
        if (
          !ts.isPropertyAssignment(property) ||
          !(ts.isIdentifier(property.name) || ts.isStringLiteral(property.name))
        )
          throw new Error("Config supports literal properties only.");
        if (Object.hasOwn(result, property.name.text))
          throw new Error("Duplicate config property.");
        result[property.name.text] = literal(property.initializer);
      }
      return result;
    }
    throw new Error(
      "Config must be literal data: functions, calls and environment access are not executed.",
    );
  }
  return validateConfig(literal(exports[0].expression));
}
export function validateConfig(value: unknown): Config {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("Config must be an object.");
  const config = value as Record<string, unknown>;
  const allowed = new Set([
    "resources",
    "principalPaths",
    "exclude",
    "maxFiles",
    "maxFileBytes",
    "verify",
  ]);
  for (const key of Object.keys(config))
    if (!allowed.has(key)) throw new Error(`Unknown config key: ${key}`);
  const strings = (v: unknown): v is string[] =>
    Array.isArray(v) && v.every((x) => typeof x === "string" && x.length > 0);
  for (const key of ["principalPaths", "exclude"])
    if (config[key] !== undefined && !strings(config[key]))
      throw new Error(`${key} must be a string array.`);
  for (const key of ["maxFiles", "maxFileBytes"])
    if (
      config[key] !== undefined &&
      (!Number.isSafeInteger(config[key]) || Number(config[key]) < 1)
    )
      throw new Error(`${key} must be a positive integer.`);
  if (config.verify !== undefined) {
    if (
      !config.verify ||
      typeof config.verify !== "object" ||
      Array.isArray(config.verify)
    )
      throw new Error("verify must be an object.");
    const verify = config.verify as Record<string, unknown>;
    const verifyAllowed = new Set([
      "allowedTargets",
      "maxRequests",
      "concurrency",
      "timeoutMs",
      "assertions",
    ]);
    for (const key of Object.keys(verify))
      if (!verifyAllowed.has(key))
        throw new Error(`Unknown verify key: ${key}`);
    if (verify.allowedTargets !== undefined && !strings(verify.allowedTargets))
      throw new Error("verify.allowedTargets must be a string array.");
    for (const key of ["maxRequests", "concurrency", "timeoutMs"])
      if (
        verify[key] !== undefined &&
        (!Number.isSafeInteger(verify[key]) || Number(verify[key]) < 1)
      )
        throw new Error(`verify.${key} must be a positive integer.`);
    if (verify.concurrency !== undefined && Number(verify.concurrency) > 8)
      throw new Error("verify.concurrency cannot exceed 8.");
    if (verify.maxRequests !== undefined && Number(verify.maxRequests) > 500)
      throw new Error("verify.maxRequests cannot exceed 500.");
    if (verify.timeoutMs !== undefined && Number(verify.timeoutMs) > 30000)
      throw new Error("verify.timeoutMs cannot exceed 30000.");
    if (!Array.isArray(verify.assertions) || verify.assertions.length === 0)
      throw new Error("verify.assertions must be a non-empty array.");
    for (const assertion of verify.assertions) {
      if (
        !assertion ||
        typeof assertion !== "object" ||
        Array.isArray(assertion)
      )
        throw new Error("Each verify assertion must be an object.");
      const item = assertion as Record<string, unknown>;
      const keys = new Set([
        "name",
        "path",
        "method",
        "expectStatus",
        "authEnv",
        "dimension",
      ]);
      for (const key of Object.keys(item))
        if (!keys.has(key))
          throw new Error(`Unknown verify assertion key: ${key}`);
      if (typeof item.name !== "string" || item.name.length < 1)
        throw new Error("verify assertion name must be a non-empty string.");
      if (
        typeof item.path !== "string" ||
        !item.path.startsWith("/") ||
        item.path.startsWith("//")
      )
        throw new Error(
          "verify assertion path must be an origin-relative path.",
        );
      if (
        item.method !== undefined &&
        item.method !== "GET" &&
        item.method !== "HEAD"
      )
        throw new Error("verify assertion method must be GET or HEAD.");
      if (
        !Number.isSafeInteger(item.expectStatus) ||
        Number(item.expectStatus) < 100 ||
        Number(item.expectStatus) > 599
      )
        throw new Error(
          "verify assertion expectStatus must be an HTTP status.",
        );
      if (
        item.authEnv !== undefined &&
        (typeof item.authEnv !== "string" ||
          !/^[A-Z_][A-Z0-9_]*$/i.test(item.authEnv))
      )
        throw new Error(
          "verify assertion authEnv must be an environment variable name.",
        );
      if (
        item.dimension !== undefined &&
        !["ownership", "tenant", "anonymous"].includes(String(item.dimension))
      )
        throw new Error("verify assertion dimension is invalid.");
    }
  }
  if (config.resources !== undefined) {
    if (
      !config.resources ||
      typeof config.resources !== "object" ||
      Array.isArray(config.resources)
    )
      throw new Error("resources must be an object.");
    for (const resource of Object.values(config.resources)) {
      if (!resource || typeof resource !== "object" || Array.isArray(resource))
        throw new Error("Resource must be an object.");
      for (const [key, fields] of Object.entries(resource))
        if (
          !["ownership", "tenant", "sensitive"].includes(key) ||
          !strings(fields)
        )
          throw new Error(`Invalid resource field: ${key}`);
    }
  }
  return config as Config;
}
