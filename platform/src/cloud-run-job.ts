import { googleApiJson, type AccessTokenProvider } from "./gcp-auth.js";

const NAME = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export class CloudRunJobClient {
  constructor(
    private readonly options: {
      projectId: string;
      region: string;
      jobName: string;
      fetchImpl?: typeof fetch;
      accessTokenProvider?: AccessTokenProvider;
    },
  ) {
    if (
      !/^[a-z][a-z0-9-]{4,62}$/.test(options.projectId) ||
      !/^[a-z0-9-]{2,32}$/.test(options.region) ||
      !NAME.test(options.jobName)
    )
      throw new Error("Cloud Run job configuration is invalid.");
  }

  async execute(input: {
    jobId: string;
    workerId: string;
    timeoutMs: number;
  }): Promise<{ operationName: string }> {
    if (
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
        input.jobId,
      ) ||
      !/^[A-Za-z0-9._:-]{1,200}$/.test(input.workerId)
    )
      throw new Error("Cloud Run execution identity is invalid.");
    if (
      !Number.isSafeInteger(input.timeoutMs) ||
      input.timeoutMs < 1_000 ||
      input.timeoutMs > 30 * 60_000
    )
      throw new Error("Cloud Run execution timeout is invalid.");

    const timeoutSeconds = Math.min(
      1_900,
      Math.ceil(input.timeoutMs / 1000) + 60,
    );
    const response = await googleApiJson<{ name?: unknown }>(
      `https://run.googleapis.com/v2/projects/${this.options.projectId}/locations/${this.options.region}/jobs/${this.options.jobName}:run`,
      {
        method: "POST",
        body: JSON.stringify({
          overrides: {
            containerOverrides: [
              {
                env: [
                  {
                    name: "REAPER_EXECUTION_JOB_ID",
                    value: input.jobId,
                  },
                  {
                    name: "REAPER_EXECUTION_WORKER_ID",
                    value: input.workerId,
                  },
                ],
              },
            ],
            taskCount: 1,
            timeout: `${timeoutSeconds}s`,
          },
        }),
      },
      {
        fetchImpl: this.options.fetchImpl,
        accessTokenProvider: this.options.accessTokenProvider,
        timeoutMs: 15_000,
      },
    );
    if (
      typeof response.name !== "string" ||
      !response.name.startsWith("projects/")
    )
      throw new Error("Cloud Run did not return a valid execution operation.");
    return { operationName: response.name };
  }
}
