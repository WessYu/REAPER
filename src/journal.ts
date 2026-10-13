import { lstat } from "node:fs/promises";
import type { VerifyJson } from "./model.js";
import {
  atomicWriteFile,
  canonicalJson,
  ensureSecureDirectory,
  listRegularFiles,
  readLimitedFile,
  safeStateFile,
  sanitizeAuditText,
  sha256,
  withExclusiveFileLock,
} from "./secure-store.js";

export type JournalStatus =
  | "PENDING"
  | "RUNNING"
  | "CLEANING"
  | "COMPLETED"
  | "INTERRUPTED"
  | "CLEANUP_FAILED"
  | "FAILED";

export type CleanupStatus = "PENDING" | "RUNNING" | "SUCCEEDED" | "FAILED";

export interface JournalIdentityRef {
  tokenEnv?: string;
  cookie?: { name: string; valueEnv: string };
  headerEnvs?: Record<string, string>;
}

export interface JournalCleanupPlan {
  id: string;
  scenarioId: string;
  stepName: string;
  method: "POST" | "PUT" | "PATCH" | "DELETE";
  path: string;
  actor?: string;
  identity?: JournalIdentityRef;
  body?: VerifyJson;
  allowedStatuses: number[];
  attempts: number;
  status: CleanupStatus;
  plannedAt: string;
  updatedAt: string;
  lastError?: string;
}

export interface ExecutionJournalRecord {
  version: 1;
  integrity: string;
  runId: string;
  workspaceId: string;
  projectId: string;
  assessmentId: string;
  targetOrigin: string;
  environment: "local" | "preview" | "staging" | "production";
  allowPrivateNetwork: boolean;
  timeoutMs: number;
  rateLimitPerSecond: number;
  maxCleanupRequests: number;
  createdAt: string;
  updatedAt: string;
  status: JournalStatus;
  cleanups: JournalCleanupPlan[];
}

export interface ExecutionJournalStore {
  create(
    input: Omit<ExecutionJournalRecord, "integrity" | "updatedAt" | "cleanups"> & {
      cleanups?: JournalCleanupPlan[];
    },
  ): Promise<ExecutionJournalRecord>;
  read(runId: string): Promise<ExecutionJournalRecord>;
  update(
    runId: string,
    mutate: (record: ExecutionJournalRecord) => void,
  ): Promise<ExecutionJournalRecord>;
  listRecoverable(): Promise<ExecutionJournalRecord[]>;
}

const MAX_JOURNAL_BYTES = 1024 * 1024;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/;
const RUN_ID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ENV_REF = /^[A-Z_][A-Z0-9_]*$/i;

function plainRecord(value: unknown): value is Record<string, unknown> {
  return (
    !!value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function timestamp(value: unknown, name: string): string {
  if (
    typeof value !== "string" ||
    !Number.isFinite(Date.parse(value)) ||
    new Date(value).toISOString() !== value
  )
    throw new Error(`Execution journal ${name} is invalid.`);
  return value;
}

function validBody(value: unknown): value is VerifyJson {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  )
    return true;
  if (Array.isArray(value)) return value.every(validBody);
  return (
    plainRecord(value) &&
    Object.entries(value).every(
      ([key, entry]) => key.length <= 200 && validBody(entry),
    )
  );
}

function validateIdentity(value: unknown): JournalIdentityRef | undefined {
  if (value === undefined) return undefined;
  if (!plainRecord(value))
    throw new Error("Execution journal cleanup identity is invalid.");
  for (const key of Object.keys(value))
    if (!["tokenEnv", "cookie", "headerEnvs"].includes(key))
      throw new Error("Execution journal cleanup identity has an unknown field.");
  if (
    value.tokenEnv !== undefined &&
    (typeof value.tokenEnv !== "string" || !ENV_REF.test(value.tokenEnv))
  )
    throw new Error("Execution journal token reference is invalid.");
  if (value.cookie !== undefined) {
    if (!plainRecord(value.cookie))
      throw new Error("Execution journal cookie reference is invalid.");
    const cookie = value.cookie;
    if (
      Object.keys(cookie).some((key) => !["name", "valueEnv"].includes(key)) ||
      typeof cookie.name !== "string" ||
      !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(cookie.name) ||
      typeof cookie.valueEnv !== "string" ||
      !ENV_REF.test(cookie.valueEnv)
    )
      throw new Error("Execution journal cookie reference is invalid.");
  }
  if (value.headerEnvs !== undefined) {
    if (
      !plainRecord(value.headerEnvs) ||
      !Object.entries(value.headerEnvs).every(
        ([name, ref]) =>
          /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) &&
          typeof ref === "string" &&
          ENV_REF.test(ref),
      )
    )
      throw new Error("Execution journal header references are invalid.");
  }
  return value as JournalIdentityRef;
}

function validateCleanup(value: unknown): JournalCleanupPlan {
  if (!plainRecord(value))
    throw new Error("Execution journal cleanup entry is invalid.");
  const allowed = new Set([
    "id",
    "scenarioId",
    "stepName",
    "method",
    "path",
    "actor",
    "identity",
    "body",
    "allowedStatuses",
    "attempts",
    "status",
    "plannedAt",
    "updatedAt",
    "lastError",
  ]);
  if (Object.keys(value).some((key) => !allowed.has(key)))
    throw new Error("Execution journal cleanup entry has an unknown field.");
  for (const field of ["id", "scenarioId", "stepName"] as const)
    if (typeof value[field] !== "string" || !ID.test(value[field]))
      throw new Error(`Execution journal cleanup ${field} is invalid.`);
  if (!["POST", "PUT", "PATCH", "DELETE"].includes(String(value.method)))
    throw new Error("Execution journal cleanup method is invalid.");
  if (
    typeof value.path !== "string" ||
    !value.path.startsWith("/") ||
    value.path.startsWith("//") ||
    value.path.length > 4096
  )
    throw new Error("Execution journal cleanup path is invalid.");
  if (
    value.actor !== undefined &&
    (typeof value.actor !== "string" || !ID.test(value.actor))
  )
    throw new Error("Execution journal cleanup actor is invalid.");
  validateIdentity(value.identity);
  if (value.body !== undefined && !validBody(value.body))
    throw new Error("Execution journal cleanup body is invalid.");
  if (
    !Array.isArray(value.allowedStatuses) ||
    value.allowedStatuses.length < 1 ||
    value.allowedStatuses.length > 20 ||
    !value.allowedStatuses.every(
      (status) =>
        Number.isSafeInteger(status) && Number(status) >= 100 && Number(status) <= 599,
    )
  )
    throw new Error("Execution journal cleanup statuses are invalid.");
  if (
    !Number.isSafeInteger(value.attempts) ||
    Number(value.attempts) < 0 ||
    Number(value.attempts) > 100
  )
    throw new Error("Execution journal cleanup attempt count is invalid.");
  if (!["PENDING", "RUNNING", "SUCCEEDED", "FAILED"].includes(String(value.status)))
    throw new Error("Execution journal cleanup status is invalid.");
  timestamp(value.plannedAt, "cleanup plannedAt");
  timestamp(value.updatedAt, "cleanup updatedAt");
  if (
    value.lastError !== undefined &&
    (typeof value.lastError !== "string" || value.lastError.length > 500)
  )
    throw new Error("Execution journal cleanup error is invalid.");
  return value as unknown as JournalCleanupPlan;
}

function withoutIntegrity(
  value: ExecutionJournalRecord,
): Omit<ExecutionJournalRecord, "integrity"> {
  const { integrity, ...rest } = value;
  void integrity;
  return rest;
}

function seal(
  value: Omit<ExecutionJournalRecord, "integrity">,
): ExecutionJournalRecord {
  return {
    ...value,
    integrity: sha256(canonicalJson(value)),
  };
}

function validateRecord(value: unknown): ExecutionJournalRecord {
  if (!plainRecord(value))
    throw new Error("Execution journal record is invalid.");
  const allowed = new Set([
    "version",
    "integrity",
    "runId",
    "workspaceId",
    "projectId",
    "assessmentId",
    "targetOrigin",
    "environment",
    "allowPrivateNetwork",
    "timeoutMs",
    "rateLimitPerSecond",
    "maxCleanupRequests",
    "createdAt",
    "updatedAt",
    "status",
    "cleanups",
  ]);
  if (Object.keys(value).some((key) => !allowed.has(key)))
    throw new Error("Execution journal record has an unknown field.");
  if (value.version !== 1)
    throw new Error("Execution journal version is unsupported.");
  if (typeof value.runId !== "string" || !RUN_ID.test(value.runId))
    throw new Error("Execution journal runId is invalid.");
  for (const field of ["workspaceId", "projectId"] as const)
    if (typeof value[field] !== "string" || !ID.test(value[field]))
      throw new Error(`Execution journal ${field} is invalid.`);
  if (
    typeof value.assessmentId !== "string" ||
    !value.assessmentId.trim() ||
    value.assessmentId.length > 200 ||
    /[\u0000-\u001f\u007f]/.test(value.assessmentId)
  )
    throw new Error("Execution journal assessmentId is invalid.");
  if (typeof value.targetOrigin !== "string") 
    throw new Error("Execution journal target is invalid.");
  const target = new URL(value.targetOrigin);
  if (
    !["http:", "https:"].includes(target.protocol) ||
    target.origin !== value.targetOrigin ||
    target.username ||
    target.password
  )
    throw new Error("Execution journal target is invalid.");
  if (!["local", "preview", "staging", "production"].includes(String(value.environment)))
    throw new Error("Execution journal environment is invalid.");
  if (typeof value.allowPrivateNetwork !== "boolean")
    throw new Error("Execution journal network flag is invalid.");
  for (const [field, max] of [
    ["timeoutMs", 30_000],
    ["rateLimitPerSecond", 20],
    ["maxCleanupRequests", 200],
  ] as const)
    if (
      !Number.isSafeInteger(value[field]) ||
      Number(value[field]) < 1 ||
      Number(value[field]) > max
    )
      throw new Error(`Execution journal ${field} is invalid.`);
  timestamp(value.createdAt, "createdAt");
  timestamp(value.updatedAt, "updatedAt");
  if (
    ![
      "PENDING",
      "RUNNING",
      "CLEANING",
      "COMPLETED",
      "INTERRUPTED",
      "CLEANUP_FAILED",
      "FAILED",
    ].includes(String(value.status))
  )
    throw new Error("Execution journal status is invalid.");
  if (
    !Array.isArray(value.cleanups) ||
    value.cleanups.length > 200 ||
    new Set(
      value.cleanups.map((cleanup) =>
        plainRecord(cleanup) ? String(cleanup.id) : "",
      ),
    ).size !== value.cleanups.length
  )
    throw new Error("Execution journal cleanup list is invalid.");
  const cleanups = value.cleanups.map(validateCleanup);
  if (typeof value.integrity !== "string" || !/^[a-f0-9]{64}$/.test(value.integrity))
    throw new Error("Execution journal integrity marker is invalid.");
  const checked = { ...(value as unknown as ExecutionJournalRecord), cleanups };
  const expected = sha256(canonicalJson(withoutIntegrity(checked)));
  if (expected !== value.integrity)
    throw new Error("Execution journal integrity verification failed.");
  return checked;
}

export class FileExecutionJournalStore implements ExecutionJournalStore {
  readonly #root: string;

  constructor(root: string) {
    this.#root = root;
  }

  async #resolvedRoot(): Promise<string> {
    return ensureSecureDirectory(this.#root);
  }

  async create(
    input: Omit<ExecutionJournalRecord, "integrity" | "updatedAt" | "cleanups"> & {
      cleanups?: JournalCleanupPlan[];
    },
  ): Promise<ExecutionJournalRecord> {
    const root = await this.#resolvedRoot();
    return withExclusiveFileLock(root, input.runId, async () => {
      const file = safeStateFile(root, `${input.runId}.json`);
      try {
        await lstat(file);
        throw new Error("Execution journal run already exists.");
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
      const record = seal({
        ...input,
        updatedAt: input.createdAt,
        cleanups: input.cleanups ?? [],
      });
      const checked = validateRecord(record);
      await atomicWriteFile(root, `${input.runId}.json`, canonicalJson(checked) + "\n");
      return checked;
    });
  }

  async read(runId: string): Promise<ExecutionJournalRecord> {
    if (!RUN_ID.test(runId)) throw new Error("Execution journal runId is invalid.");
    const root = await this.#resolvedRoot();
    const raw = await readLimitedFile(
      safeStateFile(root, `${runId}.json`),
      MAX_JOURNAL_BYTES,
    );
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw) as unknown;
    } catch {
      throw new Error("Execution journal contains invalid JSON.");
    }
    return validateRecord(parsed);
  }

  async update(
    runId: string,
    mutate: (record: ExecutionJournalRecord) => void,
  ): Promise<ExecutionJournalRecord> {
    if (!RUN_ID.test(runId)) throw new Error("Execution journal runId is invalid.");
    const root = await this.#resolvedRoot();
    return withExclusiveFileLock(root, runId, async () => {
      const raw = await readLimitedFile(
        safeStateFile(root, `${runId}.json`),
        MAX_JOURNAL_BYTES,
      );
      const current = validateRecord(JSON.parse(raw) as unknown);
      const next = structuredClone(current);
      mutate(next);
      next.updatedAt = new Date().toISOString();
      const sealed = seal(withoutIntegrity(next));
      const checked = validateRecord(sealed);
      await atomicWriteFile(root, `${runId}.json`, canonicalJson(checked) + "\n");
      return checked;
    });
  }

  async listRecoverable(): Promise<ExecutionJournalRecord[]> {
    const root = await this.#resolvedRoot();
    const records: ExecutionJournalRecord[] = [];
    for (const name of await listRegularFiles(root, ".json", 1000)) {
      const runId = name.slice(0, -5);
      if (!RUN_ID.test(runId)) continue;
      const record = await this.read(runId);
      if (["RUNNING", "INTERRUPTED", "CLEANING", "CLEANUP_FAILED"].includes(record.status))
        records.push(record);
    }
    return records.sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  }
}

export function journalError(error: unknown): string {
  return sanitizeAuditText(error instanceof Error ? error.message : "unknown error");
}
