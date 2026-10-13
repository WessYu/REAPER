import { createHash, randomUUID } from "node:crypto";
import {
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  rename,
  rm,
} from "node:fs/promises";
import path from "node:path";

const SAFE_FILE = /^[A-Za-z0-9._-]{1,220}$/;

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean")
    return JSON.stringify(value);
  if (typeof value === "number" && Number.isFinite(value))
    return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (!value || typeof value !== "object")
    throw new Error("Persistent state must contain JSON-compatible values.");
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null)
    throw new Error("Persistent state must contain plain JSON objects.");
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(",")}}`;
}

export function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

export async function ensureSecureDirectory(root: string): Promise<string> {
  const resolved = path.resolve(root);
  await mkdir(resolved, { recursive: true, mode: 0o700 });
  const stat = await lstat(resolved);
  if (!stat.isDirectory() || stat.isSymbolicLink())
    throw new Error("Persistent state root must be a real directory.");
  if (process.platform !== "win32" && (stat.mode & 0o077) !== 0)
    throw new Error(
      "Persistent state root must not be accessible by group or other users.",
    );
  return resolved;
}

export function safeStateFile(root: string, name: string): string {
  if (!SAFE_FILE.test(name))
    throw new Error("Persistent state filename is invalid.");
  const file = path.join(root, name);
  if (path.dirname(file) !== root)
    throw new Error("Persistent state path escaped its root.");
  return file;
}

export async function rejectSymlinkIfPresent(file: string): Promise<void> {
  try {
    const stat = await lstat(file);
    if (stat.isSymbolicLink())
      throw new Error("Persistent state files cannot be symbolic links.");
    if (!stat.isFile())
      throw new Error("Persistent state entry must be a regular file.");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
}

export async function readLimitedFile(
  file: string,
  maxBytes: number,
): Promise<string> {
  await rejectSymlinkIfPresent(file);
  const stat = await lstat(file);
  if (stat.size > maxBytes)
    throw new Error("Persistent state file exceeds its size limit.");
  return readFile(file, "utf8");
}

export async function atomicWriteFile(
  rootInput: string,
  name: string,
  contents: string,
): Promise<void> {
  const root = await ensureSecureDirectory(rootInput);
  const target = safeStateFile(root, name);
  await rejectSymlinkIfPresent(target);
  const temporary = safeStateFile(root, `.${name}.${randomUUID()}.tmp`);
  const handle = await open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(contents, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await rename(temporary, target);
    if (process.platform !== "win32") {
      const directory = await open(root, "r");
      try {
        await directory.sync();
      } finally {
        await directory.close();
      }
    }
  } catch (error) {
    await rm(temporary, { force: true }).catch(() => {});
    throw error;
  }
}

async function removeAbandonedLock(lock: string): Promise<boolean> {
  try {
    const raw = (await readFile(lock, "utf8")).trim();
    const pid = Number(raw);
    if (Number.isSafeInteger(pid) && pid > 0) {
      try {
        process.kill(pid, 0);
        return false;
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code !== "ESRCH") return false;
      }
    } else {
      const info = await lstat(lock);
      if (Date.now() - info.mtimeMs < 60_000) return false;
    }
    await rm(lock, { force: true });
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return true;
    return false;
  }
}

export async function withExclusiveFileLock<T>(
  rootInput: string,
  name: string,
  action: () => Promise<T>,
  options: { attempts?: number; delayMs?: number } = {},
): Promise<T> {
  const root = await ensureSecureDirectory(rootInput);
  const lock = safeStateFile(root, `${name}.lock`);
  const attempts = options.attempts ?? 80;
  const delayMs = options.delayMs ?? 25;
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  for (let attempt = 0; attempt < attempts; attempt++) {
    try {
      handle = await open(lock, "wx", 0o600);
      break;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      if (await removeAbandonedLock(lock)) continue;
      if (attempt === attempts - 1)
        throw new Error("Persistent state lock acquisition timed out.");
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
  if (!handle) throw new Error("Persistent state lock acquisition failed.");
  try {
    await handle.writeFile(String(process.pid), "utf8");
    await handle.sync();
    return await action();
  } finally {
    await handle.close().catch(() => {});
    await rm(lock, { force: true }).catch(() => {});
  }
}

export async function listRegularFiles(
  rootInput: string,
  suffix: string,
  maxEntries = 1000,
): Promise<string[]> {
  const root = await ensureSecureDirectory(rootInput);
  const names = (await readdir(root)).filter((name) => name.endsWith(suffix));
  if (names.length > maxEntries)
    throw new Error("Persistent state directory exceeds its entry limit.");
  const safe: string[] = [];
  for (const name of names) {
    if (!SAFE_FILE.test(name)) continue;
    const file = safeStateFile(root, name);
    const stat = await lstat(file);
    if (stat.isFile() && !stat.isSymbolicLink()) safe.push(name);
  }
  return safe.sort();
}

export function sanitizeAuditText(value: string, maxLength = 500): string {
  return value
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, maxLength);
}
