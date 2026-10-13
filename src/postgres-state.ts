import type { Pool, PoolClient } from "pg";
import type {
  ExecutionJournalRecord,
  ExecutionJournalStore,
  JournalCleanupPlan,
} from "./journal.js";
import type { ScopeReplayInput, ScopeReplayStore } from "./replay.js";
import type {
  AuditEvent,
  AuditEventType,
  AuditInput,
  AuditJson,
  AuditStore,
} from "./audit.js";
import {
  canonicalJson,
  sanitizeAuditText,
  sha256,
} from "./secure-store.js";

const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const GENESIS = "0".repeat(64);
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

function assertWorkspaceId(workspaceId: string): void {
  if (!UUID.test(workspaceId))
    throw new Error("PostgreSQL runner workspace id is invalid.");
}

async function withWorkspaceTransaction<T>(
  pool: Pool,
  workspaceId: string,
  work: (client: PoolClient) => Promise<T>,
): Promise<T> {
  assertWorkspaceId(workspaceId);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      "SELECT set_config('reaper.workspace_id',$1,true), set_config('reaper.principal_id',$2,true)",
      [workspaceId, "reaper-cloud-runner"],
    );
    const result = await work(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

function withoutJournalIntegrity(
  value: ExecutionJournalRecord,
): Omit<ExecutionJournalRecord, "integrity"> {
  const { integrity, ...rest } = value;
  void integrity;
  return rest;
}

function sealJournal(
  value: Omit<ExecutionJournalRecord, "integrity">,
): ExecutionJournalRecord {
  return {
    ...value,
    integrity: sha256(canonicalJson(value)),
  };
}

function verifyJournal(value: unknown): ExecutionJournalRecord {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("PostgreSQL execution journal record is invalid.");
  const record = value as ExecutionJournalRecord;
  if (
    record.version !== 1 ||
    !UUID.test(record.runId) ||
    typeof record.integrity !== "string" ||
    !/^[a-f0-9]{64}$/.test(record.integrity)
  )
    throw new Error("PostgreSQL execution journal metadata is invalid.");
  const expected = sha256(canonicalJson(withoutJournalIntegrity(record)));
  if (expected !== record.integrity)
    throw new Error("PostgreSQL execution journal integrity verification failed.");
  return structuredClone(record);
}

export class PostgresExecutionJournalStore implements ExecutionJournalStore {
  constructor(
    private readonly pool: Pool,
    private readonly workspaceId: string,
  ) {
    assertWorkspaceId(workspaceId);
  }

  async create(
    input: Omit<
      ExecutionJournalRecord,
      "integrity" | "updatedAt" | "cleanups"
    > & { cleanups?: JournalCleanupPlan[] },
  ): Promise<ExecutionJournalRecord> {
    if (input.workspaceId !== this.workspaceId)
      throw new Error("Execution journal workspace does not match runner context.");
    const record = sealJournal({
      ...input,
      updatedAt: input.createdAt,
      cleanups: input.cleanups ?? [],
    });
    await withWorkspaceTransaction(this.pool, this.workspaceId, async (client) => {
      const result = await client.query(
        `INSERT INTO reaper_control.execution_journals(
           workspace_id,run_id,record,updated_at
         ) VALUES ($1,$2,$3::jsonb,now())
         ON CONFLICT (workspace_id,run_id) DO NOTHING
         RETURNING run_id`,
        [this.workspaceId, record.runId, JSON.stringify(record)],
      );
      if (!result.rows[0])
        throw new Error("Execution journal run already exists.");
    });
    return verifyJournal(record);
  }

  async read(runId: string): Promise<ExecutionJournalRecord> {
    if (!UUID.test(runId))
      throw new Error("Execution journal runId is invalid.");
    return withWorkspaceTransaction(this.pool, this.workspaceId, async (client) => {
      const result = await client.query<{ record: unknown }>(
        `SELECT record
         FROM reaper_control.execution_journals
         WHERE workspace_id=$1 AND run_id=$2`,
        [this.workspaceId, runId],
      );
      if (!result.rows[0])
        throw new Error("Execution journal run does not exist.");
      return verifyJournal(result.rows[0].record);
    });
  }

  async update(
    runId: string,
    mutate: (record: ExecutionJournalRecord) => void,
  ): Promise<ExecutionJournalRecord> {
    if (!UUID.test(runId))
      throw new Error("Execution journal runId is invalid.");
    return withWorkspaceTransaction(this.pool, this.workspaceId, async (client) => {
      const selected = await client.query<{ record: unknown }>(
        `SELECT record
         FROM reaper_control.execution_journals
         WHERE workspace_id=$1 AND run_id=$2
         FOR UPDATE`,
        [this.workspaceId, runId],
      );
      if (!selected.rows[0])
        throw new Error("Execution journal run does not exist.");
      const current = verifyJournal(selected.rows[0].record);
      const next = structuredClone(current);
      mutate(next);
      next.updatedAt = new Date().toISOString();
      const sealed = sealJournal(withoutJournalIntegrity(next));
      await client.query(
        `UPDATE reaper_control.execution_journals
         SET record=$3::jsonb, updated_at=now()
         WHERE workspace_id=$1 AND run_id=$2`,
        [this.workspaceId, runId, JSON.stringify(sealed)],
      );
      return verifyJournal(sealed);
    });
  }

  async listRecoverable(): Promise<ExecutionJournalRecord[]> {
    return withWorkspaceTransaction(this.pool, this.workspaceId, async (client) => {
      const result = await client.query<{ record: unknown }>(
        `SELECT record
         FROM reaper_control.execution_journals
         WHERE workspace_id=$1
           AND record->>'status' = ANY($2::text[])
         ORDER BY record->>'createdAt'
         LIMIT 1000`,
        [
          this.workspaceId,
          ["RUNNING", "INTERRUPTED", "CLEANING", "CLEANUP_FAILED"],
        ],
      );
      return result.rows.map((row) => verifyJournal(row.record));
    });
  }
}

function replayText(value: string, name: string): void {
  if (
    !value ||
    value.length > 200 ||
    /[\u0000-\u001f\u007f]/.test(value)
  )
    throw new Error(`Scope replay ${name} is invalid.`);
}

function validateReplay(input: ScopeReplayInput): void {
  replayText(input.issuer, "issuer");
  replayText(input.assessmentId, "assessmentId");
  replayText(input.nonce, "nonce");
  const target = new URL(input.targetOrigin);
  if (
    !["http:", "https:"].includes(target.protocol) ||
    target.origin !== input.targetOrigin ||
    target.username ||
    target.password
  )
    throw new Error("Scope replay target origin is invalid.");
  if (
    !Number.isFinite(Date.parse(input.expiresAt)) ||
    new Date(input.expiresAt).toISOString() !== input.expiresAt
  )
    throw new Error("Scope replay expiry is invalid.");
}

export class PostgresScopeReplayStore implements ScopeReplayStore {
  constructor(
    private readonly pool: Pool,
    private readonly workspaceId: string,
  ) {
    assertWorkspaceId(workspaceId);
  }

  async consume(input: ScopeReplayInput): Promise<boolean> {
    validateReplay(input);
    return withWorkspaceTransaction(this.pool, this.workspaceId, async (client) => {
      const result = await client.query(
        `INSERT INTO reaper_control.consumed_scope_nonces(
           workspace_id,issuer,assessment_id,nonce,target_origin,expires_at
         ) VALUES ($1,$2,$3,$4,$5,$6::timestamptz)
         ON CONFLICT DO NOTHING
         RETURNING nonce`,
        [
          this.workspaceId,
          input.issuer,
          input.assessmentId,
          input.nonce,
          input.targetOrigin,
          input.expiresAt,
        ],
      );
      return Boolean(result.rows[0]);
    });
  }

  async collectExpired(now = Date.now(), maxDeletes = 100): Promise<number> {
    if (
      !Number.isSafeInteger(maxDeletes) ||
      maxDeletes < 1 ||
      maxDeletes > 1000
    )
      throw new Error("Replay-store collection limit is invalid.");
    return withWorkspaceTransaction(this.pool, this.workspaceId, async (client) => {
      const result = await client.query(
        `WITH expired AS (
           SELECT ctid
           FROM reaper_control.consumed_scope_nonces
           WHERE workspace_id=$1 AND expires_at <= $2::timestamptz
           ORDER BY expires_at
           LIMIT $3
         )
         DELETE FROM reaper_control.consumed_scope_nonces n
         USING expired
         WHERE n.ctid=expired.ctid
         RETURNING n.nonce`,
        [this.workspaceId, new Date(now).toISOString(), maxDeletes],
      );
      return result.rowCount ?? 0;
    });
  }
}

function sanitizeAuditValue(value: AuditJson, depth = 0): AuditJson {
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
    return value.map((entry) => sanitizeAuditValue(entry, depth + 1));
  }
  if (!value || typeof value !== "object")
    throw new Error("Audit event contains an unsupported value.");
  const entries = Object.entries(value);
  if (entries.length > 100)
    throw new Error("Audit event object is too large.");
  return Object.fromEntries(
    entries.map(([key, entry]) => [
      sanitizeAuditText(key, 120),
      sanitizeAuditValue(entry, depth + 1),
    ]),
  );
}

function validAuditTimestamp(value: string): string {
  if (
    !Number.isFinite(Date.parse(value)) ||
    new Date(value).toISOString() !== value
  )
    throw new Error("Audit event timestamp is invalid.");
  return value;
}

function hashAuditEvent(event: Omit<AuditEvent, "eventHash">): string {
  return sha256(canonicalJson(event));
}

function verifyAuditEvents(events: AuditEvent[], runId: string): void {
  let previous = GENESIS;
  for (let index = 0; index < events.length; index++) {
    const event = events[index]!;
    if (
      event.version !== 1 ||
      event.runId !== runId ||
      event.sequence !== index + 1 ||
      event.previousHash !== previous ||
      !EVENT_TYPES.has(event.type)
    )
      throw new Error("PostgreSQL audit trail chain metadata is invalid.");
    validAuditTimestamp(event.at);
    const expected = hashAuditEvent({
      version: 1,
      runId,
      sequence: event.sequence,
      previousHash: previous,
      type: event.type,
      at: event.at,
      data: event.data,
    });
    if (expected !== event.eventHash)
      throw new Error("PostgreSQL audit trail integrity verification failed.");
    previous = event.eventHash;
  }
}

export class PostgresAuditStore implements AuditStore {
  constructor(
    private readonly pool: Pool,
    private readonly workspaceId: string,
  ) {
    assertWorkspaceId(workspaceId);
  }

  async append(runId: string, input: AuditInput): Promise<AuditEvent> {
    if (!UUID.test(runId)) throw new Error("Audit runId is invalid.");
    if (!EVENT_TYPES.has(input.type))
      throw new Error("Audit event type is invalid.");
    return withWorkspaceTransaction(this.pool, this.workspaceId, async (client) => {
      await client.query(
        `SELECT id
         FROM reaper_control.runs
         WHERE workspace_id=$1 AND id=$2
         FOR UPDATE`,
        [this.workspaceId, runId],
      );
      const last = await client.query<{
        sequence: string;
        event_hash: string;
      }>(
        `SELECT sequence,event_hash
         FROM reaper_control.audit_events
         WHERE workspace_id=$1 AND run_id=$2
         ORDER BY sequence DESC
         LIMIT 1`,
        [this.workspaceId, runId],
      );
      const sequence = last.rows[0] ? Number(last.rows[0].sequence) + 1 : 1;
      if (!Number.isSafeInteger(sequence) || sequence > 5000)
        throw new Error("Audit trail exceeds its event limit.");
      const previousHash = last.rows[0]?.event_hash ?? GENESIS;
      const data = sanitizeAuditValue((input.data ?? {}) as AuditJson) as Record<
        string,
        AuditJson
      >;
      const base = {
        version: 1 as const,
        runId,
        sequence,
        previousHash,
        type: input.type,
        at: validAuditTimestamp(input.at ?? new Date().toISOString()),
        data,
      };
      const event: AuditEvent = {
        ...base,
        eventHash: hashAuditEvent(base),
      };
      await client.query(
        `INSERT INTO reaper_control.audit_events(
           workspace_id,run_id,sequence,previous_hash,event_hash,event_type,payload,created_at
         ) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8::timestamptz)`,
        [
          this.workspaceId,
          runId,
          sequence,
          event.previousHash,
          event.eventHash,
          event.type,
          JSON.stringify(event.data),
          event.at,
        ],
      );
      await client.query(
        `INSERT INTO reaper_control.audit_heads(
           workspace_id,run_id,sequence,event_hash,updated_at
         ) VALUES ($1,$2,$3,$4,now())
         ON CONFLICT (workspace_id,run_id)
         DO UPDATE SET sequence=EXCLUDED.sequence,event_hash=EXCLUDED.event_hash,updated_at=now()`,
        [this.workspaceId, runId, sequence, event.eventHash],
      );
      return event;
    });
  }

  async read(runId: string): Promise<AuditEvent[]> {
    if (!UUID.test(runId)) throw new Error("Audit runId is invalid.");
    return withWorkspaceTransaction(this.pool, this.workspaceId, async (client) => {
      const result = await client.query<{
        sequence: string;
        previous_hash: string;
        event_hash: string;
        event_type: AuditEventType;
        payload: Record<string, AuditJson>;
        created_at: Date;
      }>(
        `SELECT sequence,previous_hash,event_hash,event_type,payload,created_at
         FROM reaper_control.audit_events
         WHERE workspace_id=$1 AND run_id=$2
         ORDER BY sequence
         LIMIT 5001`,
        [this.workspaceId, runId],
      );
      if (result.rows.length > 5000)
        throw new Error("Audit trail exceeds its event limit.");
      const events = result.rows.map((row) => ({
        version: 1 as const,
        runId,
        sequence: Number(row.sequence),
        previousHash: row.previous_hash,
        eventHash: row.event_hash,
        type: row.event_type,
        at: new Date(row.created_at).toISOString(),
        data: row.payload,
      }));
      verifyAuditEvents(events, runId);
      return events;
    });
  }

  async verify(runId: string): Promise<boolean> {
    const events = await this.read(runId);
    return withWorkspaceTransaction(this.pool, this.workspaceId, async (client) => {
      const head = await client.query<{
        sequence: string;
        event_hash: string;
      }>(
        `SELECT sequence,event_hash
         FROM reaper_control.audit_heads
         WHERE workspace_id=$1 AND run_id=$2`,
        [this.workspaceId, runId],
      );
      if (events.length === 0) return !head.rows[0];
      const last = events.at(-1)!;
      if (
        !head.rows[0] ||
        Number(head.rows[0].sequence) !== last.sequence ||
        head.rows[0].event_hash !== last.eventHash
      )
        throw new Error("Audit trail truncation or head mismatch detected.");
      return true;
    });
  }
}
