function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(name + " is required.");
  return value;
}

async function githubOidcToken(): Promise<string> {
  const requestUrl = new URL(required("ACTIONS_ID_TOKEN_REQUEST_URL"));
  if (
    requestUrl.protocol !== "https:" ||
    !requestUrl.hostname.endsWith("actions.githubusercontent.com")
  )
    throw new Error("GitHub OIDC request URL is invalid.");
  requestUrl.searchParams.set("audience", "reaper-staging");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5_000);
  try {
    const response = await fetch(requestUrl, {
      headers: {
        authorization:
          "Bearer " + required("ACTIONS_ID_TOKEN_REQUEST_TOKEN"),
      },
      redirect: "error",
      signal: controller.signal,
    });
    if (!response.ok)
      throw new Error(
        "GitHub OIDC token request returned HTTP " + response.status + ".",
      );
    const body = (await response.json()) as { value?: unknown };
    if (typeof body.value !== "string" || body.value.length < 100)
      throw new Error("GitHub OIDC token response is invalid.");
    return body.value;
  } finally {
    clearTimeout(timeout);
  }
}

async function gateway<T>(
  path: string,
  body: Record<string, unknown>,
): Promise<T> {
  const base = required("REAPER_FREE_RUNNER_API");
  if (!base.startsWith("https://"))
    throw new Error("REAPER_FREE_RUNNER_API must use HTTPS.");
  const token = await githubOidcToken();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15_000);
  try {
    const response = await fetch(base.replace(/\/$/, "") + path, {
      method: "POST",
      headers: {
        authorization: "Bearer " + token,
        "content-type": "application/json",
      },
      body: JSON.stringify(body),
      redirect: "error",
      signal: controller.signal,
    });
    const text = await response.text();
    const value = text ? JSON.parse(text) : {};
    if (!response.ok)
      throw new Error(
        "Free runner gateway returned HTTP " +
          response.status +
          ": " +
          String(value?.error ?? "request failed").slice(0, 500),
      );
    return value as T;
  } finally {
    clearTimeout(timeout);
  }
}

function validateLease(job: unknown): asserts job is {
  id: string;
  workspaceId: string;
  runId: string;
  workerId: string;
  payload: {
    projectId: string;
    assessmentId: string;
    targetOrigin: string;
    environment: "preview" | "staging";
    configPath: "free-readonly.ts";
    permissions: ["read"];
    limits: {
      maxRequests: number;
      maxCleanupRequests: number;
      rateLimitPerSecond: number;
      deadlineMs: number;
    };
  };
} {
  if (!job || typeof job !== "object" || Array.isArray(job))
    throw new Error("Free runner lease is invalid.");
  const value = job as Record<string, unknown>;
  const payload =
    value.payload && typeof value.payload === "object"
      ? (value.payload as Record<string, unknown>)
      : {};
  const limits =
    payload.limits && typeof payload.limits === "object"
      ? (payload.limits as Record<string, unknown>)
      : {};
  const target =
    typeof payload.targetOrigin === "string"
      ? new URL(payload.targetOrigin)
      : undefined;
  if (
    typeof value.id !== "string" ||
    typeof value.workspaceId !== "string" ||
    typeof value.runId !== "string" ||
    typeof value.workerId !== "string" ||
    typeof payload.projectId !== "string" ||
    typeof payload.assessmentId !== "string" ||
    !target ||
    target.protocol !== "https:" ||
    target.origin !== payload.targetOrigin ||
    !["preview", "staging"].includes(String(payload.environment)) ||
    payload.configPath !== "free-readonly.ts" ||
    !Array.isArray(payload.permissions) ||
    payload.permissions.length !== 1 ||
    payload.permissions[0] !== "read" ||
    !Number.isSafeInteger(limits.maxRequests) ||
    Number(limits.maxRequests) < 1 ||
    Number(limits.maxRequests) > 8 ||
    !Number.isSafeInteger(limits.maxCleanupRequests) ||
    Number(limits.maxCleanupRequests) < 1 ||
    Number(limits.maxCleanupRequests) > 1 ||
    !Number.isSafeInteger(limits.rateLimitPerSecond) ||
    Number(limits.rateLimitPerSecond) < 1 ||
    Number(limits.rateLimitPerSecond) > 2 ||
    !Number.isSafeInteger(limits.deadlineMs) ||
    Number(limits.deadlineMs) < 1000 ||
    Number(limits.deadlineMs) > 60_000
  )
    throw new Error("Free runner lease escaped its read-only safety profile.");
}

function freeConfig(job: {
  payload: {
    assessmentId: string;
    targetOrigin: string;
    environment: "preview" | "staging";
    limits: {
      maxRequests: number;
      maxCleanupRequests: number;
      rateLimitPerSecond: number;
      deadlineMs: number;
    };
  };
}) {
  return {
    attack: {
      allowedTargets: [job.payload.targetOrigin],
      authorization: {
        acknowledged: true,
        reference: job.payload.assessmentId,
        environment: job.payload.environment,
        expiresAt: new Date(Date.now() + 5 * 60_000).toISOString(),
      },
      maxRequests: Math.min(8, job.payload.limits.maxRequests),
      maxCleanupRequests: 1,
      timeoutMs: Math.min(5_000, job.payload.limits.deadlineMs),
      rateLimitPerSecond: Math.min(
        2,
        job.payload.limits.rateLimitPerSecond,
      ),
      maxConsecutiveServerErrors: 2,
      allowMutations: false,
      allowPrivateNetwork: false,
      requireSignedScope: false,
      scenarios: [
        {
          id: "free-readonly-root",
          title: "Free staging read-only root boundary probe",
          dimension: "business-logic",
          severity: "INFO",
          steps: [
            {
              name: "probe root without credentials or mutations",
              path: "/",
              method: "GET",
              expect: {
                allowedStatuses: [
                  200, 204, 301, 302, 307, 308, 400, 401, 403, 404, 405, 429,
                ],
              },
            },
          ],
        },
      ],
    },
  };
}

async function main(): Promise<void> {
  const lease = await gateway<{ job: unknown }>("/runner/lease", {});
  if (!lease.job) {
    console.log(
      JSON.stringify({
        event: "reaper.free-runner.idle",
        provider: "github-actions",
      }),
    );
    return;
  }

  validateLease(lease.job);
  const job = lease.job;
  console.log(
    JSON.stringify({
      event: "reaper.free-runner.leased",
      runId: job.runId,
      jobId: job.id,
    }),
  );

  try {
    const rootDist = new URL("../../dist/", import.meta.url);
    const engine = (await import(new URL("index.js", rootDist).href)) as {
      runAttack: (
        target: string,
        config: unknown,
        options?: Record<string, unknown>,
      ) => Promise<Record<string, unknown>>;
    };

    const report = await engine.runAttack(
      job.payload.targetOrigin,
      freeConfig(job),
      {
        runId: job.runId,
        workspaceId: job.workspaceId,
        projectId: job.payload.projectId,
      },
    );

    const serialized = JSON.stringify(report);
    if (Buffer.byteLength(serialized, "utf8") > 480 * 1024)
      throw new Error("Free runner report exceeds the 480 KiB gateway limit.");

    await gateway("/runner/complete", {
      jobId: job.id,
      report,
    });
    console.log(
      JSON.stringify({
        event: "reaper.free-runner.completed",
        runId: job.runId,
        jobId: job.id,
      }),
    );
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "free runner execution failed";
    await gateway("/runner/fail", {
      jobId: job.id,
      error: message.slice(0, 500),
    }).catch(() => {});
    throw error;
  }
}

main().catch((error: unknown) => {
  console.error(
    error instanceof Error ? error.message : "free runner execution failed",
  );
  process.exitCode = 2;
});
