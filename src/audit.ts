import {
  atomicWriteFile,
  canonicalJson,
  ensureSecureDirectory,
  readLimitedFile,
  safeStateFile,
  sanitizeAuditText,
  sha256,
  withExclusiveFileLock,
} from "./secure-store.js";

export type AuditEventType =
  | "RUN_CREATED"
  | "SCOPE_VERIFIED"
  | "SCOPE_CONSUMED"
  | "RUN_STARTED"
  | "REQUEST_EXECUTED"
  | "FINDING_CONFIRMED"
  | "CLEANUP_PLANNED"
  | "CLEANUP_STARTED"
  | "CLEANUP_SUCCEEDED"
  | "CLEANUP_FAILED"
  | "RUN_INTERRUPTED"
  | "RUN_FAILED"
  | "RUN_COMPLETED"
  | "RECOVERY_STARTED"
  | "RECOVERY_COMPLETED";

export type AuditJson =
  | string
  | number
  | boolean
  | null
  | AuditJson[]
  | { [key: string]: AuditJson };

export interface AuditInput {
  type: AuditEventType;
  at?: string;
  data?: Record<string, AuditJson>;
}

export interface AuditEvent {
  version: 1;
  runId: string;
  sequence: number;
  previousHash: string;
  eventHash: string;
  type: AuditEventType;
  at: string;
  data: Record<string, AuditJson>;
}

export interface AuditStore {
  append(runId: string, event: AuditInput): Promise<AuditEvent>;
  read(runId: string): Promise<AuditEvent[]>;
  verify(runId: string): Promise<boolean>;
}

const GENESIS = "0".repeat(64);
const RUN_ID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_AUDIT_BYTES = 4 * 1024 * 1024;
const MAX_EVENTS = 5000;
const EVENT_TYPES = new Set<AuditEventType>([
  "RUN_CREATED",
  "SCOPE_VERIFIED",
  "SCOPE_CONSUMED",
  "RUN_STARTED",
  "REQUEST_EXECUTED",
  "FINDING_CONFIRMED",
  "CLEANUP_PLANNED",
  "CLEANUP_STARTED",
  "CLEANUP_SUCCEEDED",
  "CLEANUP_FAILED",
  "RUN_INTERRUPTED",
  "RUN_FAILED",
  "RUN_COMPLETED",
  "RECOVERY_STARTED",
  "RECOVERY_COMPLETED",
]);

function sanitizeValue(value: AuditJson, depth = 0): AuditJson {
  if (depth > 8) throw new Error("Audit event exceeds the nesting limit.");
  if (typeof value === "string") return sanitizeAuditText(value, 1000);
  if (
    value === null ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value))
  )
    return value;
  if (Array.isArray(value)) {
    if (value.length > 100) throw new Error("Audit event array is too large.");
    return value.map((entry) => sanitizeValue(entry, depth + 1));
  }
  if (!value || typeof value !== "object")
    throw new Error("Audit event contains an unsupported value.");
  if (Object.getPrototypeOf(value) !== Object.prototype)
    throw new Error("Audit event objects must be plain JSON.");
  const entries = Object.entries(value);
  if (entries.length > 100) throw new Error("Audit event object is too large.");
  return Object.fromEntries(
    entries.map(([key, entry]) => [
      sanitizeAuditText(key, 120),
      sanitizeValue(entry, depth + 1),
    ]),
  );
}

function eventPayload(
  event: Omit<AuditEvent, "eventHash">,
): Omit<AuditEvent, "eventHash"> {
  return event;
}

function hashEvent(event: Omit<AuditEvent, "eventHash">): string {
  return sha256(canonicalJson(eventPayload(event)));
}

function validateTimestamp(value: unknown): string {
  if (
    typeof value !== "string" ||
    !Number.isFinite(Date.parse(value)) ||
    new Date(value).toISOString() !== value
  )
    throw new Error("Audit event timestamp is invalid.");
  return value;
}

function parseEvents(raw: string, expectedRunId: string): AuditEvent[] {
  if (!raw.trim()) return [];
  const lines = raw.trimEnd().split("\n");
  if (lines.length > MAX_EVENTS)
    throw new Error("Audit trail exceeds its event limit.");
  const events: AuditEvent[] = [];
  let previous = GENESIS;
  for (let index = 0; index < lines.length; index++) {
    let value: unknown;
    try {
      value = JSON.parse(lines[index]!) as unknown;
    } catch {
      throw new Error("Audit trail contains invalid JSON.");
    }
    if (!value || typeof value !== "object" || Array.isArray(value))
      throw new Error("Audit trail event is invalid.");
    const event = value as Record<string, unknown>;
    const allowed = [
      "version",
      "runId",
      "sequence",
      "previousHash",
      "eventHash",
      "type",
      "at",
      "data",
    ];
    if (Object.keys(event).some((key) => !allowed.includes(key)))
      throw new Error("Audit trail event contains an unknown field.");
    if (
      event.version !== 1 ||
      event.runId !== expectedRunId ||
      event.sequence !== index + 1 ||
      event.previousHash !== previous ||
      typeof event.eventHash !== "string" ||
      !/^[a-f0-9]{64}$/.test(event.eventHash) ||
      typeof event.type !== "string" ||
      !EVENT_TYPES.has(event.type as AuditEventType)
    )
      throw new Error("Audit trail chain metadata is invalid.");
    validateTimestamp(event.at);
    if (
      !event.data ||
      typeof event.data !== "object" ||
      Array.isArray(event.data) ||
      Object.getPrototypeOf(event.data) !== Object.prototype
    )
      throw new Error("Audit trail data is invalid.");
    const candidate = {
      version: 1 as const,
      runId: expectedRunId,
      sequence: index + 1,
      previousHash: previous,
      type: event.type as AuditEventType,
      at: event.at as string,
      data: event.data as Record<string, AuditJson>,
    };
    const expectedHash = hashEvent(candidate);
    if (expectedHash !== event.eventHash)
      throw new Error("Audit trail integrity verification failed.");
    const checked = { ...candidate, eventHash: expectedHash };
    events.push(checked);
    previous = expectedHash;
  }
  return events;
}

async function readAudit(root: string, runId: string): Promise<AuditEvent[]> {
  const file = safeStateFile(root, `${runId}.audit.jsonl`);
  try {
    return parseEvents(await readLimitedFile(file, MAX_AUDIT_BYTES), runId);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw error;
  }
}

export class FileAuditStore implements AuditStore {
  readonly #root: string;

  constructor(root: string) {
    this.#root = root;
  }

  async append(runId: string, input: AuditInput): Promise<AuditEvent> {
    if (!RUN_ID.test(runId)) throw new Error("Audit runId is invalid.");
    if (!EVENT_TYPES.has(input.type))
      throw new Error("Audit event type is invalid.");
    const root = await ensureSecureDirectory(this.#root);
    return withExclusiveFileLock(root, `${runId}.audit`, async () => {
      const events = await readAudit(root, runId);
      if (events.length >= MAX_EVENTS)
        throw new Error("Audit trail exceeds its event limit.");
      const previous = events.at(-1)?.eventHash ?? GENESIS;
      const data = sanitizeValue((input.data ?? {}) as AuditJson) as Record<
        string,
        AuditJson
      >;
      const base = {
        version: 1 as const,
        runId,
        sequence: events.length + 1,
        previousHash: previous,
        type: input.type,
        at: validateTimestamp(input.at ?? new Date().toISOString()),
        data,
      };
      const next: AuditEvent = { ...base, eventHash: hashEvent(base) };
      const serialized =
        [...events, next].map((event) => canonicalJson(event)).join("\n") +
        "\n";
      if (Buffer.byteLength(serialized, "utf8") > MAX_AUDIT_BYTES)
        throw new Error("Audit trail exceeds its size limit.");
      await atomicWriteFile(root, `${runId}.audit.jsonl`, serialized);
      await atomicWriteFile(
        root,
        `${runId}.audit.head.json`,
        canonicalJson({
          version: 1,
          runId,
          sequence: next.sequence,
          eventHash: next.eventHash,
        }) + "\n",
      );
      return next;
    });
  }

  async read(runId: string): Promise<AuditEvent[]> {
    if (!RUN_ID.test(runId)) throw new Error("Audit runId is invalid.");
    const root = await ensureSecureDirectory(this.#root);
    return readAudit(root, runId);
  }

  async verify(runId: string): Promise<boolean> {
    const events = await this.read(runId);
    if (events.length === 0) return true;
    const root = await ensureSecureDirectory(this.#root);
    let head: unknown;
    try {
      head = JSON.parse(
        await readLimitedFile(
          safeStateFile(root, `${runId}.audit.head.json`),
          4096,
        ),
      ) as unknown;
    } catch {
      throw new Error("Audit trail head anchor is missing or invalid.");
    }
    if (!head || typeof head !== "object" || Array.isArray(head))
      throw new Error("Audit trail head anchor is invalid.");
    const record = head as Record<string, unknown>;
    const last = events.at(-1)!;
    if (
      record.version !== 1 ||
      record.runId !== runId ||
      record.sequence !== last.sequence ||
      record.eventHash !== last.eventHash
    )
      throw new Error("Audit trail truncation or head mismatch detected.");
    return true;
  }
}

export async function verifyAuditChain(
  store: AuditStore,
  runId: string,
): Promise<boolean> {
  return store.verify(runId);
}
