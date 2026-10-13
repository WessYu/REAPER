import { open, rm } from "node:fs/promises";
import {
  canonicalJson,
  ensureSecureDirectory,
  listRegularFiles,
  readLimitedFile,
  safeStateFile,
  sha256,
} from "./secure-store.js";

export interface ScopeReplayInput {
  issuer: string;
  assessmentId: string;
  nonce: string;
  targetOrigin: string;
  expiresAt: string;
}

export interface ScopeReplayStore {
  consume(input: ScopeReplayInput): Promise<boolean>;
  collectExpired?(now?: number, maxDeletes?: number): Promise<number>;
}

function replayKey(input: ScopeReplayInput): string {
  return sha256(
    canonicalJson({
      issuer: input.issuer,
      assessmentId: input.assessmentId,
      nonce: input.nonce,
      targetOrigin: input.targetOrigin,
    }),
  );
}

function validate(input: ScopeReplayInput): void {
  for (const [name, value] of Object.entries({
    issuer: input.issuer,
    assessmentId: input.assessmentId,
    nonce: input.nonce,
  }))
    if (
      typeof value !== "string" ||
      !value.trim() ||
      value.length > 200 ||
      /[\u0000-\u001f\u007f]/.test(value)
    )
      throw new Error(`Scope replay ${name} is invalid.`);
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

export class InMemoryScopeReplayStore implements ScopeReplayStore {
  readonly #used = new Set<string>();

  async consume(input: ScopeReplayInput): Promise<boolean> {
    validate(input);
    const key = replayKey(input);
    if (this.#used.has(key)) return false;
    this.#used.add(key);
    return true;
  }
}

export class FileScopeReplayStore implements ScopeReplayStore {
  readonly #root: string;

  constructor(root: string) {
    this.#root = root;
  }

  async consume(input: ScopeReplayInput): Promise<boolean> {
    validate(input);
    const root = await ensureSecureDirectory(this.#root);
    const key = replayKey(input);
    const file = safeStateFile(root, `${key}.nonce`);
    let handle: Awaited<ReturnType<typeof open>>;
    try {
      handle = await open(file, "wx", 0o600);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") return false;
      throw error;
    }
    try {
      const record = canonicalJson({
        version: 1,
        key,
        expiresAt: input.expiresAt,
      });
      await handle.writeFile(record + "\n", "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
    return true;
  }

  async collectExpired(now = Date.now(), maxDeletes = 100): Promise<number> {
    if (
      !Number.isSafeInteger(maxDeletes) ||
      maxDeletes < 1 ||
      maxDeletes > 1000
    )
      throw new Error("Replay-store collection limit is invalid.");
    const root = await ensureSecureDirectory(this.#root);
    let removed = 0;
    for (const name of await listRegularFiles(root, ".nonce", 5000)) {
      if (removed >= maxDeletes) break;
      const file = safeStateFile(root, name);
      const raw = await readLimitedFile(file, 4096);
      let record: unknown;
      try {
        record = JSON.parse(raw) as unknown;
      } catch {
        continue;
      }
      if (
        !record ||
        typeof record !== "object" ||
        Array.isArray(record) ||
        typeof (record as { expiresAt?: unknown }).expiresAt !== "string"
      )
        continue;
      const expires = Date.parse((record as { expiresAt: string }).expiresAt);
      if (Number.isFinite(expires) && expires <= now) {
        await rm(file, { force: true });
        removed++;
      }
    }
    return removed;
  }
}
