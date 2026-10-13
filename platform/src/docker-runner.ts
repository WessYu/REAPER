import { spawn } from "node:child_process";
import { chown, mkdir, readFile, rm } from "node:fs/promises";
import path from "node:path";
import type { PlatformJob } from "./types.js";
import { buildScopePayload, type ScopeSigner } from "./scope-signer.js";

interface RunnerOutcome {
  status: "COMPLETED" | "FAILED" | "INTERRUPTED" | "CLEANUP_FAILED";
  exitCode: number | null;
  reason?: string;
  result?: unknown;
}

function safeRelative(value: string): string {
  if (
    value.startsWith("/") ||
    value.includes("\\") ||
    value.split("/").some((part) => !part || part === "..")
  )
    throw new Error("Runner config path is unsafe.");
  return value;
}

function numericIdentity(): string {
  const configured = process.env.REAPER_PLATFORM_CONTAINER_UID;
  if (configured) {
    if (!/^\d+(?::\d+)?$/.test(configured) || configured.startsWith("0"))
      throw new Error(
        "REAPER_PLATFORM_CONTAINER_UID must be a non-root numeric uid[:gid].",
      );
    return configured;
  }
  const uid = process.getuid?.();
  const gid = process.getgid?.();
  if (!uid || uid === 0 || gid === undefined || gid === 0)
    throw new Error(
      "A non-root REAPER_PLATFORM_CONTAINER_UID is required when the worker runs as root.",
    );
  return { value: `${uid}:${gid}`, uid, gid };
}

export class DockerRunner {
  constructor(
    private readonly options: {
      image: string;
      network: string;
      configRoot: string;
      stateRoot: string;
      outputRoot: string;
      signer: ScopeSigner;
    },
  ) {
    if (!options.image.trim()) throw new Error("Runner image is required.");
    if (!/^[A-Za-z0-9_.-]+$/.test(options.network))
      throw new Error("A preconfigured isolated Docker network is required.");
  }

  async run(job: PlatformJob): Promise<RunnerOutcome> {
    const permissions = job.payload.permissions ?? ["read"];
    const limits = {
      maxRequests: job.payload.limits?.maxRequests ?? 20,
      maxCleanupRequests: job.payload.limits?.maxCleanupRequests ?? 10,
      rateLimitPerSecond: job.payload.limits?.rateLimitPerSecond ?? 5,
      deadlineMs: job.payload.limits?.deadlineMs ?? 120_000,
    };
    const scopePayload = buildScopePayload({
      runId: job.runId,
      assessmentId: job.payload.assessmentId,
      workspaceId: job.workspaceId,
      target: job.payload.targetOrigin,
      environment: job.payload.environment,
      permissions,
      limits,
    });
    const scope = await this.options.signer.sign(scopePayload);

    const identity = numericIdentity();
    const stateDirectory = path.resolve(this.options.stateRoot, job.runId);
    const outputDirectory = path.resolve(this.options.outputRoot, job.runId);
    await mkdir(stateDirectory, { recursive: true, mode: 0o700 });
    await mkdir(outputDirectory, { recursive: true, mode: 0o700 });
    if (process.getuid?.() === 0) {
      await chown(stateDirectory, identity.uid, identity.gid);
      await chown(outputDirectory, identity.uid, identity.gid);
    }
    const reportFile = path.join(outputDirectory, "outcome.json");
    await rm(reportFile, { force: true });
    const configPath = safeRelative(job.payload.configPath);

    const args = [
      "run",
      "--rm",
      "--name",
      `reaper-run-${job.runId}`,
      "--network",
      this.options.network,
      "--read-only",
      "--cap-drop=ALL",
      "--security-opt=no-new-privileges:true",
      "--memory=512m",
      "--cpus=1",
      "--pids-limit=128",
      "--user",
      identity.value,
      "--tmpfs",
      "/tmp:rw,noexec,nosuid,size=64m",
      "--mount",
      `type=bind,src=${path.resolve(this.options.configRoot)},dst=/reaper-config,readonly`,
      "--mount",
      `type=bind,src=${stateDirectory},dst=/reaper-state`,
      "--mount",
      `type=bind,src=${outputDirectory},dst=/reaper-output`,
      "--env",
      "REAPER_CONTAINER_ENFORCED=1",
      "--env",
      `REAPER_RUN_ID=${job.runId}`,
      "--env",
      `REAPER_WORKSPACE_ID=${job.workspaceId}`,
      "--env",
      `REAPER_PROJECT_ID=${job.payload.projectId}`,
      "--env",
      `REAPER_ASSESSMENT_ID=${job.payload.assessmentId}`,
      "--env",
      `REAPER_TARGET_ORIGIN=${job.payload.targetOrigin}`,
      "--env",
      `REAPER_ENVIRONMENT=${job.payload.environment}`,
      "--env",
      `REAPER_CONFIG_FILE=/reaper-config/${configPath}`,
      "--env",
      "REAPER_OUTPUT_FILE=/reaper-output/outcome.json",
      "--env",
      "REAPER_STATE_DIRECTORY=/reaper-state",
      "--env",
      `REAPER_SCOPE_MANIFEST=${JSON.stringify(scope)}`,
      "--env",
      `REAPER_SCOPE_PUBLIC_KEY=${this.options.signer.publicKeyPem}`,
      this.options.image,
    ];

    const exitCode = await new Promise<number>((resolve, reject) => {
      const child = spawn("docker", args, {
        stdio: ["ignore", "pipe", "pipe"],
        env: { PATH: process.env.PATH },
      });
      let stderr = "";
      child.stdout.on("data", () => {
        // Drain stdout so a noisy container cannot block on a full pipe.
      });
      child.stderr.on("data", (chunk: Buffer) => {
        if (stderr.length < 16_384) stderr += chunk.toString("utf8");
      });
      child.once("error", reject);
      child.once("close", (code) => {
        if (code !== 0 && stderr.trim())
          process.stderr.write(stderr.slice(0, 16_384));
        resolve(code ?? 2);
      });
    });

    let outcome: RunnerOutcome;
    try {
      outcome = JSON.parse(await readFile(reportFile, "utf8")) as RunnerOutcome;
    } catch {
      return {
        status: "FAILED",
        exitCode,
        reason: "runner did not produce a valid outcome",
      };
    }
    return outcome;
  }
}
