import path from "node:path";
import { Pool } from "pg";
import { runAttack } from "./attack.js";
import { FileExecutionJournalStore } from "./journal.js";
import { FileScopeReplayStore } from "./replay.js";
import { FileAuditStore } from "./audit.js";
import {
  PostgresExecutionJournalStore,
  PostgresScopeReplayStore,
  PostgresAuditStore,
} from "./postgres-state.js";
import type { AttackJob } from "./runner.js";

let activeController: AbortController | undefined;
let started = false;

function sendAndExit(message: object, code: number): void {
  process.send?.(message, undefined, undefined, () => process.exit(code));
}

process.on("message", (message: unknown) => {
  if (
    message &&
    typeof message === "object" &&
    (message as { type?: unknown }).type === "cancel"
  ) {
    activeController?.abort();
    return;
  }
  if (started) return;
  started = true;
  void (async () => {
    try {
      if (
        !message ||
        typeof message !== "object" ||
        (message as { type?: unknown }).type !== "job" ||
        typeof (message as { json?: unknown }).json !== "string" ||
        Buffer.byteLength((message as { json: string }).json, "utf8") >
          5 * 1024 * 1024
      )
        throw new Error("invalid job envelope");
      const job = JSON.parse((message as { json: string }).json) as AttackJob;
      const stateDirectory = process.env.REAPER_RUNNER_STATE_DIR;
      const databaseUrl = process.env.REAPER_RUNNER_DATABASE_URL;
      const workspaceId = process.env.REAPER_RUNNER_WORKSPACE_ID;
      const strictCommercial = process.env.REAPER_RUNNER_MODE === "strict";
      if (strictCommercial && !stateDirectory && !databaseUrl)
        throw new Error("strict runner durable state backend is unavailable");
      if (databaseUrl && !workspaceId)
        throw new Error("PostgreSQL runner state requires a workspace id");
      if (stateDirectory && databaseUrl)
        throw new Error("runner state backend is ambiguous");

      const pool = databaseUrl
        ? new Pool({
            connectionString: databaseUrl,
            max: 1,
            application_name: "reaper-cloud-runner",
          })
        : undefined;
      const journalStore = pool && workspaceId
        ? new PostgresExecutionJournalStore(pool, workspaceId)
        : stateDirectory
          ? new FileExecutionJournalStore(path.join(stateDirectory, "journal"))
          : undefined;
      const scopeReplayStore = pool && workspaceId
        ? new PostgresScopeReplayStore(pool, workspaceId)
        : stateDirectory
          ? new FileScopeReplayStore(path.join(stateDirectory, "replay"))
          : undefined;
      const auditStore = pool && workspaceId
        ? new PostgresAuditStore(pool, workspaceId)
        : stateDirectory
          ? new FileAuditStore(path.join(stateDirectory, "audit"))
          : undefined;
      activeController = new AbortController();
      const result = await runAttack(job.target, job.config, {
        signal: activeController.signal,
        runId: job.runId,
        rulePackVersion: job.rulePackVersion,
        workspaceId: job.workspaceId,
        projectId: job.projectId,
        scopeManifest: job.scopeManifest,
        trustedScopeKeys: job.trustedScopeKeys,
        strictCommercial,
        journalStore,
        scopeReplayStore,
        auditStore,
      });
      await pool?.end();
      const json = JSON.stringify(result);
      if (typeof json !== "string")
        throw new Error("result serialization failed");
      if (Buffer.byteLength(json, "utf8") > job.limits.maxOutputBytes) {
        sendAndExit({ type: "error", code: "report-limit" }, 1);
        return;
      }
      sendAndExit({ type: "result", json }, 0);
    } catch {
      sendAndExit({ type: "error", code: "ENGINE_FAILURE" }, 1);
    }
  })();
});
