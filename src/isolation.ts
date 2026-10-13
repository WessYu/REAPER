import { fork, type ChildProcess } from "node:child_process";

export interface RunnerIsolationCapabilities {
  processIsolation: boolean;
  filesystemIsolation: boolean;
  networkIsolation: boolean;
  resourceLimits: boolean;
}

export interface RunnerSpawnInput {
  modulePath: string;
  cwd: string;
  env: NodeJS.ProcessEnv;
  execArgv: string[];
}

export interface RunnerIsolationProvider {
  readonly name: string;
  readonly capabilities: RunnerIsolationCapabilities;
  spawn(input: RunnerSpawnInput): ChildProcess;
}

export type RunnerIsolationMode = "standard" | "strict";

export class ProcessIsolationProvider implements RunnerIsolationProvider {
  readonly name = "node-child-process";
  readonly capabilities: RunnerIsolationCapabilities = {
    processIsolation: true,
    filesystemIsolation: false,
    networkIsolation: false,
    resourceLimits: false,
  };

  spawn(input: RunnerSpawnInput): ChildProcess {
    return fork(input.modulePath, [], {
      cwd: input.cwd,
      env: input.env,
      execArgv: input.execArgv,
      stdio: ["ignore", "pipe", "pipe", "ipc"],
      serialization: "json",
    });
  }
}

export function assertRunnerIsolation(
  mode: RunnerIsolationMode,
  provider: RunnerIsolationProvider,
): void {
  if (!provider || typeof provider.spawn !== "function")
    throw new Error("Runner isolation provider is invalid.");
  const capabilities = provider.capabilities;
  if (
    !capabilities ||
    typeof capabilities.processIsolation !== "boolean" ||
    typeof capabilities.filesystemIsolation !== "boolean" ||
    typeof capabilities.networkIsolation !== "boolean" ||
    typeof capabilities.resourceLimits !== "boolean"
  )
    throw new Error("Runner isolation capabilities are invalid.");
  if (!capabilities.processIsolation)
    throw new Error("Runner requires process isolation.");
  if (
    mode === "strict" &&
    (!capabilities.filesystemIsolation ||
      !capabilities.networkIsolation ||
      !capabilities.resourceLimits)
  )
    throw new Error(
      "Strict runner mode requires filesystem isolation, network isolation and enforceable resource limits.",
    );
}
