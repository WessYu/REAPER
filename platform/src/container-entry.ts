import { fork, type ChildProcess } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import type { SignedAuthorizationScope } from "./scope-signer.js";

interface IsolationInput {
  modulePath: string;
  cwd: string;
  env: NodeJS.ProcessEnv;
  execArgv: string[];
}

class OuterContainerIsolationProvider {
  readonly name = "hardened-outer-container";
  readonly capabilities = {
    processIsolation: true,
    filesystemIsolation: true,
    networkIsolation: true,
    resourceLimits: true,
  };

  spawn(input: IsolationInput): ChildProcess {
    if (process.env.REAPER_CONTAINER_ENFORCED !== "1")
      throw new Error("Outer container isolation attestation is missing.");
    return fork(input.modulePath, [], {
      cwd: input.cwd,
      env: input.env,
      execArgv: input.execArgv,
      stdio: ["ignore", "pipe", "pipe", "ipc"],
      serialization: "json",
    });
  }
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required.`);
  return value;
}

async function main(): Promise<void> {
  const rootDist = new URL("../../dist/", import.meta.url);
  const engine = (await import(new URL("index.js", rootDist).href)) as {
    runAttackJob: (job: unknown, options: unknown) => Promise<unknown>;
  };
  const configModule = (await import(new URL("config.js", rootDist).href)) as {
    readConfig: (file: string) => Promise<Record<string, unknown>>;
  };
  const model = (await import(new URL("model.js", rootDist).href)) as {
    ENGINE_VERSION: string;
  };

  const runId = required("REAPER_RUN_ID");
  const workspaceId = required("REAPER_WORKSPACE_ID");
  const projectId = required("REAPER_PROJECT_ID");
  const assessmentId = required("REAPER_ASSESSMENT_ID");
  const target = required("REAPER_TARGET_ORIGIN");
  const environment = required("REAPER_ENVIRONMENT") as
    | "local"
    | "preview"
    | "staging"
    | "production";
  const configFile = required("REAPER_CONFIG_FILE");
  const outputFile = required("REAPER_OUTPUT_FILE");
  const stateDirectory = required("REAPER_STATE_DIRECTORY");
  const scope = JSON.parse(required("REAPER_SCOPE_MANIFEST")) as SignedAuthorizationScope;
  const publicKey = required("REAPER_SCOPE_PUBLIC_KEY");

  const base = await configModule.readConfig(configFile);
  const baseAttack =
    base.attack && typeof base.attack === "object"
      ? (base.attack as Record<string, unknown>)
      : {};
  const authorization =
    baseAttack.authorization && typeof baseAttack.authorization === "object"
      ? (baseAttack.authorization as Record<string, unknown>)
      : {};

  const config = {
    ...base,
    attack: {
      ...baseAttack,
      allowedTargets: [target],
      requireSignedScope: true,
      authorization: {
        ...authorization,
        acknowledged: true,
        reference: assessmentId,
        environment,
        expiresAt: scope.payload.expiresAt,
      },
      maxRequests: scope.payload.limits.maxRequests,
      maxCleanupRequests: scope.payload.limits.maxCleanupRequests,
      rateLimitPerSecond: scope.payload.limits.rateLimitPerSecond,
    },
  };

  const now = new Date();
  const job = {
    version: 1,
    runId,
    target,
    authorization: {
      reference: assessmentId,
      environment,
      expiresAt: scope.payload.expiresAt,
    },
    config,
    limits: {
      deadlineMs: scope.payload.limits.deadlineMs,
      cleanupGraceMs: Math.min(60_000, Math.max(5_000, scope.payload.limits.deadlineMs / 10)),
      memoryMb: 384,
      maxOutputBytes: 8 * 1024 * 1024,
    },
    engineVersion: model.ENGINE_VERSION,
    createdAt: now.toISOString(),
    deadline: new Date(now.getTime() + scope.payload.limits.deadlineMs).toISOString(),
    workspaceId,
    projectId,
    scopeManifest: scope,
    trustedScopeKeys: { [scope.keyId]: publicKey },
  };

  const outcome = await engine.runAttackJob(job, {
    isolationMode: "strict",
    isolationProvider: new OuterContainerIsolationProvider(),
    stateDirectory,
  });

  await writeFile(outputFile, JSON.stringify(outcome), {
    encoding: "utf8",
    mode: 0o600,
  });

  const status =
    outcome && typeof outcome === "object"
      ? (outcome as { status?: string }).status
      : undefined;
  if (status !== "COMPLETED") process.exitCode = 2;
}

main().catch(async (error: unknown) => {
  const output = process.env.REAPER_OUTPUT_FILE;
  if (output) {
    const message = error instanceof Error ? error.message : "runner failed";
    await writeFile(
      path.resolve(output),
      JSON.stringify({ status: "FAILED", exitCode: 2, reason: message }),
      { encoding: "utf8", mode: 0o600 },
    ).catch(() => {});
  }
  process.exitCode = 2;
});
