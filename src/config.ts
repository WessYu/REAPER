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
