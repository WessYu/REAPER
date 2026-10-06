import { readdir, readFile, lstat, realpath } from "node:fs/promises";
import path from "node:path";
import type { Config, Diagnostic } from "./model.js";
export async function discover(
  root: string,
  config: Config,
  diagnostics: Diagnostic[],
): Promise<string[]> {
  const files: string[] = [];
  const ignored = new Set([
    "node_modules",
    ".git",
    "dist",
    "build",
    ".next",
    "coverage",
    "vendor",
    ".turbo",
    ...(config.exclude ?? []),
  ]);
  async function walk(directory: string): Promise<void> {
    for (const entry of (
      await readdir(directory, { withFileTypes: true })
    ).sort((a, b) => a.name.localeCompare(b.name))) {
      if (ignored.has(entry.name) || entry.isSymbolicLink()) continue;
      const file = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        await walk(file);
        continue;
      }
      if (
        !/\.(?:[cm]?[jt]sx?|prisma)$/.test(entry.name) ||
        /(?:\.d\.ts|\.generated\.[jt]s)$/.test(entry.name)
      )
        continue;
      if ((await lstat(file)).size > (config.maxFileBytes ?? 1_000_000)) {
        diagnostics.push({
          file: path.relative(root, file),
          message: "File exceeds maxFileBytes; not analyzed.",
        });
        continue;
      }
      if (files.length >= (config.maxFiles ?? 10000))
        throw new Error(
          "Project exceeds maxFiles. Narrow the scan root or increase the limit.",
        );
      files.push(file);
    }
  }
  await walk(await realpath(root));
  return files;
}
export async function inferResources(
  files: string[],
): Promise<NonNullable<Config["resources"]>> {
  const result: NonNullable<Config["resources"]> = {};
  for (const file of files.filter((f) => f.endsWith(".prisma"))) {
    const source = (await readFile(file, "utf8")).replace(/\/\/[^\n]*/g, "");
    for (const model of source.matchAll(/model\s+(\w+)\s*\{([^}]+)\}/g)) {
      const name = model[1]!;
      const body = model[2]!;
      const ownership: string[] = [],
        tenant: string[] = [],
        sensitive: string[] = [];
      // Field names alone are insufficient: require an explicit Prisma relation.
      for (const relation of body.matchAll(
        /\b(\w+)\s+(\w+)\??\s+@relation\s*\(\s*(?:"[^"]*"\s*,\s*)?fields\s*:\s*\[([^\]]+)\]/g,
      )) {
        const target = relation[2]!.toLowerCase();
        const fields = relation[3]!.split(",").map((v) => v.trim());
        if (["user", "owner"].includes(target)) ownership.push(...fields);
        if (["tenant", "organization", "workspace", "account"].includes(target))
          tenant.push(...fields);
      }
      const sensitiveNames = new Set([
        "password",
        "passwordhash",
        "passwd",
        "refreshtoken",
        "resettoken",
        "apikey",
        "secret",
        "clientsecret",
        "privatekey",
        "cpf",
        "ssn",
        "cardtoken",
        "bankaccount",
      ]);
      for (const field of body.matchAll(/^\s*(\w+)\s+[\w\[\]?]+/gm)) {
        const fieldName = field[1]!;
        if (sensitiveNames.has(fieldName.replaceAll("_", "").toLowerCase()))
          sensitive.push(fieldName);
      }
      result[name[0]!.toLowerCase() + name.slice(1)] = {
        ownership,
        tenant,
        sensitive,
      };
    }
  }
  return result;
}
