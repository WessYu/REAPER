import { randomUUID } from "node:crypto";
import { createPlatformPool } from "./db.js";
import { DockerRunner } from "./docker-runner.js";
import { PlatformRepository } from "./repository.js";
import { RemoteScopeSigner } from "./scope-signer.js";

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required.`);
  return value;
}

async function main(): Promise<void> {
  const pool = createPlatformPool(required("REAPER_PLATFORM_DATABASE_URL"));
  const repository = new PlatformRepository(
    pool,
    required("REAPER_PLATFORM_API_KEY_PEPPER"),
  );
  const signer = new RemoteScopeSigner(
    required("REAPER_PLATFORM_SIGNER_URL"),
    required("REAPER_PLATFORM_SIGNER_TOKEN"),
    required("REAPER_PLATFORM_SCOPE_PUBLIC_KEY"),
  );
  const runner = new DockerRunner({
    image: required("REAPER_PLATFORM_RUNNER_IMAGE"),
    network: required("REAPER_PLATFORM_DOCKER_NETWORK"),
    configRoot: required("REAPER_PLATFORM_CONFIG_ROOT"),
    stateRoot: required("REAPER_PLATFORM_STATE_ROOT"),
    outputRoot: required("REAPER_PLATFORM_OUTPUT_ROOT"),
    signer,
  });
  const workerId =
    process.env.REAPER_PLATFORM_WORKER_ID ?? `worker-${randomUUID()}`;
  let stopping = false;
  process.once("SIGINT", () => {
    stopping = true;
  });
  process.once("SIGTERM", () => {
    stopping = true;
  });

  try {
    while (!stopping) {
      const job = await repository.leaseJob(workerId, 180);
      if (!job) {
        await new Promise((resolve) => setTimeout(resolve, 1_000));
        continue;
      }
      try {
        const outcome = await runner.run(job);
        if (outcome.status === "COMPLETED") {
          await repository.completeJob(
            job,
            workerId,
            outcome.result ?? outcome,
          );
        } else {
          await repository.failJob(
            job,
            workerId,
            new Error(outcome.reason ?? outcome.status),
            job.attempt < 3 ? Math.min(300, 15 * 2 ** (job.attempt - 1)) : 0,
          );
        }
      } catch (error) {
        await repository.failJob(
          job,
          workerId,
          error,
          job.attempt < 3 ? Math.min(300, 15 * 2 ** (job.attempt - 1)) : 0,
        );
      }
    }
  } finally {
    await pool.end();
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 2;
});
