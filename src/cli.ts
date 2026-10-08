#!/usr/bin/env node
import { parseArgs } from "node:util";
import { readFile, writeFile, access } from "node:fs/promises";
import path from "node:path";
import { scan } from "./scan.js";
import {
  introspect,
  analyzeDatabase,
  type DatabaseSnapshot,
} from "./postgres.js";
import { correlateSourceDatabase } from "./correlation.js";
import { report, fails } from "./reporter.js";
import { calculateScore, renderScore } from "./score.js";
import { renderGraph } from "./graph.js";
import { renderExplanation } from "./explain.js";
import { verify } from "./verify.js";
import { readConfig } from "./config.js";
import { renderDashboard } from "./dashboard.js";
import { createReaperServer } from "./server.js";
import type { ScanResult } from "./model.js";
const help = `REAPER 0.2.0 — Data Access Security Engine

reaper scan [path]       Analyze supported JS/TS handlers and data access
reaper sql [path]        Show SQL findings
reaper authz [path]      Show ownership findings
reaper tenants [path]    Show tenant findings
reaper supabase [path]   Show Supabase-specific findings
reaper migrations [path] Show SQL migration security findings
reaper crypto [path]     Show secret and password-crypto findings
reaper rls              Inspect PostgreSQL catalogs and RLS
reaper privileges       Inspect PostgreSQL table grants
reaper schema           Export read-only PostgreSQL catalog snapshot
reaper baseline <json>  Export finding fingerprints from a JSON report
reaper diff <old> <new> Compare two JSON reports by fingerprint
reaper report <json>    Render a saved JSON report
reaper explain <id> --input <json>
reaper graph <json>      Render report graph as JSON or DOT
reaper score <json>      Calculate an explainable score from a saved report
reaper verify <target>    Run configured authorization scenarios
reaper discover <target>  Discover GET/HEAD routes from allowlisted OpenAPI docs
reaper dashboard <json>  Render a self-contained HTML security dashboard
reaper serve [path]       Start a localhost-only REST service and dashboard
reaper doctor           Check runtime version

--config <file>          Literal reaper.config.ts (never executed)
--format <format>        terminal | json | sarif | markdown
--output <file>          Write output instead of stdout
--fail-on <severity>     Exit 1 on new findings at/above threshold
--baseline <file>        JSON array of accepted fingerprints
--db-env <name>          Environment variable holding database URL
--help | --version

Exit 0: completed, gate passed; 1: gate failed; 2: error/incomplete analysis.
Runtime verification is authorization-scoped: localhost or exact allowlist, bounded discovery, explicit assertions and opt-in synthetic setup/teardown.
`;
async function main(): Promise<void> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    strict: true,
    options: {
      help: { type: "boolean" },
      version: { type: "boolean" },
      config: { type: "string" },
      format: { type: "string" },
      output: { type: "string" },
      "fail-on": { type: "string" },
      baseline: { type: "string" },
      "db-env": { type: "string" },
      input: { type: "string" },
      port: { type: "string" },
    },
  });
  if (values.help || (positionals.length === 0 && !values.version)) {
    process.stdout.write(help);
    return;
  }
  if (values.version) {
    process.stdout.write("0.2.0\n");
    return;
  }
  const [command, arg, second] = positionals;
  const format = values.format ?? "terminal";
  if (!["terminal", "json", "sarif", "markdown", "dot"].includes(format))
    throw new Error("Unsupported format.");
  if (values["fail-on"]) fails([], values["fail-on"]);
  const output = async (text: string) => {
    if (values.output) await writeFile(values.output, text, { mode: 0o600 });
    else process.stdout.write(text);
  };
  const json = async (file: string) =>
    JSON.parse(await readFile(file, "utf8")) as unknown;
  const saved = async (file: string | undefined): Promise<ScanResult> => {
    if (!file) throw new Error("A JSON report path is required.");
    const data = (await json(file)) as ScanResult;
    if (
      !["0.1.0", "0.1.1", "0.2.0"].includes(data?.version) ||
      !Array.isArray(data.findings) ||
      !data.metrics ||
      !Array.isArray(data.diagnostics)
    )
      throw new Error("Invalid REAPER report.");
    return data;
  };
  if (command === "dashboard") {
    const rendered = renderDashboard(await saved(arg));
    await output(rendered);
    return;
  }
  if (command === "serve") {
    const root = path.resolve(arg ?? ".");
    const port = values.port ? Number(values.port) : 7337;
    if (!Number.isSafeInteger(port) || port < 1 || port > 65535)
      throw new Error("--port must be a valid TCP port.");
    const server = await createReaperServer({
      root,
      configFile: values.config,
      port,
    });
    process.stdout.write(
      `REAPER local service: http://127.0.0.1:${server.port}\nPress Ctrl+C to stop.\n`,
    );
    const close = () => {
      server.server.close();
    };
    process.once("SIGINT", close);
    process.once("SIGTERM", close);
    await new Promise<void>((resolve) => server.server.once("close", resolve));
    return;
  }
  if (command === "doctor") {
    await output(
      `Node ${process.versions.node}; supported: ${Number(process.versions.node.split(".")[0]) >= 22}\n`,
    );
    return;
  }
  if (command === "discover") {
    if (!arg) throw new Error("discover requires a target URL.");
    if (!values.config) throw new Error("discover requires --config.");
    const verifyConfig = await readConfig(values.config);
    const { discoverEndpoints } = await import("./verify.js");
    const endpoints = await discoverEndpoints(arg, verifyConfig);
    await output(JSON.stringify(endpoints, null, 2) + "\n");
    return;
  }
  if (command === "verify") {
    if (!arg) throw new Error("verify requires a target URL.");
    if (!values.config)
      throw new Error(
        "verify requires --config with literal verify assertions.",
      );
    const verifyConfig = await readConfig(values.config);
    const controller = new AbortController();
    const cancel = () => controller.abort();
    process.once("SIGINT", cancel);
    const result = await verify(arg, verifyConfig, {
      signal: controller.signal,
    }).finally(() => process.removeListener("SIGINT", cancel));
    await output(report(result, format));
    if (result.diagnostics.length) process.exitCode = 2;
    else if (values["fail-on"] && fails(result.findings, values["fail-on"]))
      process.exitCode = 1;
    return;
  }
  if (command === "baseline") {
    await output(
      JSON.stringify(
        (await saved(arg)).findings
          .filter((f) => f.status !== "suppressed")
          .map((f) => f.fingerprint),
        null,
        2,
      ) + "\n",
    );
    return;
  }
  if (command === "diff") {
    const old = await saved(arg),
      current = await saved(second),
      before = new Set(old.findings.map((f) => f.fingerprint)),
      after = new Set(current.findings.map((f) => f.fingerprint));
    await output(
      JSON.stringify(
        {
          added: current.findings.filter((f) => !before.has(f.fingerprint)),
          resolved: old.findings.filter((f) => !after.has(f.fingerprint)),
        },
        null,
        2,
      ) + "\n",
    );
    return;
  }
  if (command === "graph") {
    const graphFormat = format === "dot" ? "dot" : "json";
    if (!["json", "dot"].includes(graphFormat))
      throw new Error("Graph format must be json or dot.");
    await output(renderGraph((await saved(arg)).graph, graphFormat));
    return;
  }
  if (command === "score") {
    const scored = calculateScore(await saved(arg));
    await output(renderScore(scored, format));
    return;
  }
  if (command === "explain") {
    const f = (await saved(values.input)).findings.find((f) => f.id === arg);
    if (!f) throw new Error("Finding ID not found in report.");
    await output(renderExplanation(f, format));
    return;
  }
  let result: ScanResult;
  if (command === "report") result = await saved(arg);
  else if (["rls", "privileges", "schema"].includes(command!)) {
    const env = values["db-env"] ?? "DATABASE_URL";
    const url = process.env[env];
    if (!url) throw new Error(`Environment variable ${env} is not set.`);
    const snapshot = await introspect(url);
    if (command === "schema") {
      await output(JSON.stringify(snapshot, null, 2) + "\n");
      return;
    }
    result = {
      version: "0.2.0",
      root: "database",
      findings: analyzeDatabase(snapshot).filter((f) =>
        command === "rls" ? f.category === "RLS" : f.category === "Privileges",
      ),
      diagnostics: [],
      graph: { nodes: [], edges: [] },
      metrics: {
        files: 0,
        routes: 0,
        sinks: 0,
        durationMs: 0,
        memoryBytes: process.memoryUsage().rss,
      },
      coverage: { source: false, database: true, runtime: false },
    };
  } else if (
    [
      "scan",
      "sql",
      "authz",
      "tenants",
      "supabase",
      "migrations",
      "crypto",
    ].includes(command!)
  ) {
    const root = path.resolve(arg ?? ".");
    let configFile = values.config;
    if (!configFile) {
      const candidate = path.join(root, "reaper.config.ts");
      try {
        await access(candidate);
        configFile = candidate;
      } catch (error) {
        if (
          !(
            error &&
            typeof error === "object" &&
            "code" in error &&
            error.code === "ENOENT"
          )
        )
          throw error;
      }
    }
    const baseline = values.baseline ? await json(values.baseline) : undefined;
    if (
      baseline !== undefined &&
      (!Array.isArray(baseline) ||
        !baseline.every(
          (f) => typeof f === "string" && /^[a-f0-9]{64}$/.test(f),
        ))
    )
      throw new Error("Invalid baseline fingerprint array.");
    result = await scan({
      root,
      configFile,
      baseline: baseline as string[] | undefined,
    });
    if (values["db-env"]) {
      const url = process.env[values["db-env"]];
      if (!url)
        throw new Error(`Environment variable ${values["db-env"]} is not set.`);
      const snapshot: DatabaseSnapshot = await introspect(url);
      const databaseFindings = [
        ...analyzeDatabase(snapshot),
        ...correlateSourceDatabase(result, snapshot),
      ];
      const accepted = new Set(
        Array.isArray(baseline) ? (baseline as string[]) : [],
      );
      for (const finding of databaseFindings)
        if (accepted.has(finding.fingerprint)) finding.status = "baseline";
      result.findings = [...result.findings, ...databaseFindings].sort(
        (a, b) =>
          a.file.localeCompare(b.file) ||
          a.line - b.line ||
          a.ruleId.localeCompare(b.ruleId),
      );
      result.coverage.database = true;
    }
    const categories: Record<string, string> = {
      sql: "SQL Safety",
      authz: "Authorization",
      tenants: "Tenant Isolation",
      supabase: "Supabase",
      migrations: "Migrations",
      crypto: "Secrets & Crypto",
    };
    if (categories[command!])
      result.findings = result.findings.filter(
        (f) => f.category === categories[command!],
      );
  } else throw new Error(`Unknown command: ${command}. Run reaper --help.`);
  await output(report(result, format));
  if (result.diagnostics.length) process.exitCode = 2;
  else if (values["fail-on"] && fails(result.findings, values["fail-on"]))
    process.exitCode = 1;
}
main().catch((error) => {
  process.stderr.write(
    `REAPER: ${error instanceof Error ? error.message : "Unexpected error"}\n`,
  );
  process.exitCode = 2;
});
