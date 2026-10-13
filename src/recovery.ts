import { executeRecordedCleanup } from "./attack.js";
import type { AuditStore } from "./audit.js";
import {
  journalError,
  type ExecutionJournalRecord,
  type ExecutionJournalStore,
  type JournalCleanupPlan,
} from "./journal.js";
import type { SecretProvider } from "./secrets.js";

export interface RecoveryResult {
  runId: string;
  status: "COMPLETED" | "CLEANUP_FAILED" | "INCOMPLETE";
  attempted: number;
  succeeded: number;
  failed: number;
}

export interface RecoveryOptions {
  auditStore: AuditStore;
  secretProvider?: SecretProvider;
  allowStale?: boolean;
  maxAgeMs?: number;
  claimStaleMs?: number;
}

function recoverable(record: ExecutionJournalRecord): boolean {
  return ["RUNNING", "INTERRUPTED", "CLEANING", "CLEANUP_FAILED"].includes(
    record.status,
  );
}

function stale(record: ExecutionJournalRecord, maxAgeMs: number): boolean {
  return Date.now() - Date.parse(record.updatedAt) > maxAgeMs;
}

async function claimCleanup(
  store: ExecutionJournalStore,
  runId: string,
  cleanupId: string,
  claimStaleMs: number,
): Promise<JournalCleanupPlan | undefined> {
  let claimed: JournalCleanupPlan | undefined;
  await store.update(runId, (record) => {
    const plan = record.cleanups.find(
      (candidate) => candidate.id === cleanupId,
    );
    if (!plan || plan.status === "SUCCEEDED") return;
    if (
      plan.status === "RUNNING" &&
      Date.now() - Date.parse(plan.updatedAt) < claimStaleMs
    )
      return;
    plan.status = "RUNNING";
    plan.attempts++;
    plan.updatedAt = new Date().toISOString();
    delete plan.lastError;
    record.status = "CLEANING";
    claimed = structuredClone(plan);
  });
  return claimed;
}

async function completeCleanup(
  store: ExecutionJournalStore,
  runId: string,
  cleanupId: string,
): Promise<void> {
  await store.update(runId, (record) => {
    const plan = record.cleanups.find(
      (candidate) => candidate.id === cleanupId,
    );
    if (!plan) throw new Error("Recovery cleanup plan disappeared.");
    plan.status = "SUCCEEDED";
    plan.updatedAt = new Date().toISOString();
    delete plan.lastError;
  });
}

async function failCleanup(
  store: ExecutionJournalStore,
  runId: string,
  cleanupId: string,
  error: unknown,
): Promise<void> {
  await store.update(runId, (record) => {
    const plan = record.cleanups.find(
      (candidate) => candidate.id === cleanupId,
    );
    if (!plan) throw new Error("Recovery cleanup plan disappeared.");
    plan.status = "FAILED";
    plan.updatedAt = new Date().toISOString();
    plan.lastError = journalError(error);
    record.status = "CLEANUP_FAILED";
  });
}

export async function recoverAttackRun(
  journalStore: ExecutionJournalStore,
  runId: string,
  options: RecoveryOptions,
): Promise<RecoveryResult> {
  const maxAgeMs = options.maxAgeMs ?? 7 * 24 * 60 * 60_000;
  const claimStaleMs = options.claimStaleMs ?? 60_000;
  if (!Number.isSafeInteger(maxAgeMs) || maxAgeMs < 1000)
    throw new Error("Recovery maxAgeMs is invalid.");
  if (!Number.isSafeInteger(claimStaleMs) || claimStaleMs < 1000)
    throw new Error("Recovery claimStaleMs is invalid.");

  const initial = await journalStore.read(runId);
  if (!recoverable(initial))
    throw new Error("Execution journal is not in a recoverable state.");
  if (!options.allowStale && stale(initial, maxAgeMs))
    throw new Error(
      "Execution journal is stale; operator approval is required for recovery.",
    );

  await options.auditStore.append(runId, {
    type: "RECOVERY_STARTED",
    data: {
      previousStatus: initial.status,
      pendingCleanups: initial.cleanups.filter(
        (plan) => plan.status !== "SUCCEEDED",
      ).length,
    },
  });

  let attempted = 0;
  let succeeded = 0;
  let failed = 0;
  const ordered = [...initial.cleanups];
  for (const candidate of ordered) {
    if (candidate.status === "SUCCEEDED") continue;
    const plan = await claimCleanup(
      journalStore,
      runId,
      candidate.id,
      claimStaleMs,
    );
    if (!plan) continue;
    attempted++;
    await options.auditStore.append(runId, {
      type: "CLEANUP_STARTED",
      data: {
        scenarioId: plan.scenarioId,
        step: plan.stepName,
        recovery: true,
        attempt: plan.attempts,
      },
    });
    try {
      const result = await executeRecordedCleanup(
        await journalStore.read(runId),
        plan,
        { secretProvider: options.secretProvider },
      );
      await completeCleanup(journalStore, runId, plan.id);
      succeeded++;
      await options.auditStore.append(runId, {
        type: "CLEANUP_SUCCEEDED",
        data: {
          scenarioId: plan.scenarioId,
          step: plan.stepName,
          recovery: true,
          status: result.status,
        },
      });
    } catch (error) {
      failed++;
      await failCleanup(journalStore, runId, plan.id, error);
      await options.auditStore.append(runId, {
        type: "CLEANUP_FAILED",
        data: {
          scenarioId: plan.scenarioId,
          step: plan.stepName,
          recovery: true,
          error: journalError(error),
        },
      });
    }
  }

  const after = await journalStore.read(runId);
  const remaining = after.cleanups.filter(
    (plan) => plan.status !== "SUCCEEDED",
  );
  const terminal: RecoveryResult["status"] = remaining.some(
    (plan) => plan.status === "FAILED",
  )
    ? "CLEANUP_FAILED"
    : remaining.length > 0
      ? "INCOMPLETE"
      : "COMPLETED";

  if (terminal !== "INCOMPLETE")
    await journalStore.update(runId, (record) => {
      record.status = terminal;
    });

  await options.auditStore.append(runId, {
    type: "RECOVERY_COMPLETED",
    data: {
      status: terminal,
      attempted,
      succeeded,
      failed,
      remaining: remaining.length,
    },
  });

  return { runId, status: terminal, attempted, succeeded, failed };
}

export async function recoverPendingAttackRuns(
  journalStore: ExecutionJournalStore,
  options: RecoveryOptions & { maxRuns?: number },
): Promise<RecoveryResult[]> {
  const maxRuns = options.maxRuns ?? 25;
  if (!Number.isSafeInteger(maxRuns) || maxRuns < 1 || maxRuns > 100)
    throw new Error("Recovery run limit is invalid.");
  const records = (await journalStore.listRecoverable()).slice(0, maxRuns);
  const results: RecoveryResult[] = [];
  for (const record of records) {
    if (
      !options.allowStale &&
      stale(record, options.maxAgeMs ?? 7 * 24 * 60 * 60_000)
    )
      continue;
    results.push(await recoverAttackRun(journalStore, record.runId, options));
  }
  return results;
}
