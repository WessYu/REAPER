import {
  googleApiJson,
  type AccessTokenProvider,
} from "./gcp-auth.js";

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
    executionEnvelope: string;
    timeoutMs: number;
  }): Promise<{ operationName: string }> {
    if (
      !/^[A-Za-z0-9_-]+$/.test(input.executionEnvelope) ||
      Buffer.byteLength(input.executionEnvelope, "utf8") > 900_000
    )
      throw new Error("Cloud Run execution envelope is invalid or too large.");
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
                    name: "REAPER_EXECUTION_ENVELOPE_B64",
                    value: input.executionEnvelope,
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
