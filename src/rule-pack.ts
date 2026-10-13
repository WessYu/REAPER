import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
  KeyObject,
  type KeyLike,
} from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import path from "node:path";
import { finding } from "./findings.js";
import {
  ENGINE_VERSION,
  type Category,
  type ScanResult,
  type Severity,
} from "./model.js";

export interface RulePackRule {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  category: Category;
  contains: string;
  caseSensitive?: boolean;
  fileExtensions?: string[];
  recommendation: string;
}

export interface RulePackPayload {
  formatVersion: 1;
  packId: string;
  version: string;
  compatibility: { engineVersions: string[] };
  rules: RulePackRule[];
}

export interface SignedRulePack {
  keyId: string;
  payload: RulePackPayload;
  hash: string;
  signature: string;
}

const severities = new Set<Severity>([
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFO",
]);
const categories = new Set<Category>([
  "SQL Safety",
  "Authorization",
  "Tenant Isolation",
  "RLS",
  "Privileges",
  "Supabase",
  "Migrations",
  "Secrets & Crypto",
  "Runtime Verification",
  "Offensive Validation",
]);
const semver = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const maxPackBytes = 1_048_576;
const maxRules = 100;
const maxMatchesPerRuleFile = 20;
const maxFindings = 2_000;
const maxFiles = 5_000;
const maxSourceBytes = 100 * 1024 * 1024;

function canonical(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean")
    return JSON.stringify(value);
  if (typeof value === "number" && Number.isFinite(value))
    return JSON.stringify(value);
  if (Array.isArray(value)) {
    const entries: string[] = [];
    for (let index = 0; index < value.length; index++) {
      if (!(index in value))
        throw new Error("Rule pack contains a sparse array.");
      entries.push(canonical(value[index]));
    }
    return `[${entries.join(",")}]`;
  }
  if (typeof value !== "object")
    throw new Error("Rule pack contains a non-JSON value.");
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null)
    throw new Error("Rule pack must contain plain JSON objects.");
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`).join(",")}}`;
}

function text(value: unknown, field: string, max: number, min = 1): string {
  if (
    typeof value !== "string" ||
    value.length < min ||
    value.length > max ||
    /[\u0000-\u001f\u007f]/.test(value)
  )
    throw new Error(`Rule pack ${field} is invalid.`);
  return value;
}

function exactKeys(record: Record<string, unknown>, allowed: string[]): void {
  if (Object.keys(record).some((key) => !allowed.includes(key)))
    throw new Error("Rule pack contains an unsupported field.");
}

function validatePayload(value: unknown): RulePackPayload {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("Rule pack payload is invalid.");
  const payload = value as Record<string, unknown>;
  exactKeys(payload, [
    "formatVersion",
    "packId",
    "version",
    "compatibility",
    "rules",
  ]);
  if (payload.formatVersion !== 1)
    throw new Error("Rule pack format version is unsupported.");
  const packId = text(payload.packId, "packId", 50);
  if (!/^[a-z0-9][a-z0-9-]*$/.test(packId))
    throw new Error("Rule pack packId is invalid.");
  const version = text(payload.version, "version", 40);
  if (!semver.test(version)) throw new Error("Rule pack version is invalid.");

  if (
    !payload.compatibility ||
    typeof payload.compatibility !== "object" ||
    Array.isArray(payload.compatibility)
  )
    throw new Error("Rule pack compatibility is invalid.");
  const compatibility = payload.compatibility as Record<string, unknown>;
  exactKeys(compatibility, ["engineVersions"]);
  if (
    !Array.isArray(compatibility.engineVersions) ||
    compatibility.engineVersions.length < 1 ||
    compatibility.engineVersions.length > 10 ||
    compatibility.engineVersions.some(
      (entry) => typeof entry !== "string" || !semver.test(entry),
    ) ||
    new Set(compatibility.engineVersions).size !==
      compatibility.engineVersions.length
  )
    throw new Error("Rule pack engine compatibility is invalid.");

  if (
    !Array.isArray(payload.rules) ||
    payload.rules.length < 1 ||
    payload.rules.length > maxRules
  )
    throw new Error(`Rule pack must contain between 1 and ${maxRules} rules.`);
  const ruleIds = new Set<string>();
  const rules = payload.rules.map((raw) => {
    if (!raw || typeof raw !== "object" || Array.isArray(raw))
      throw new Error("Rule pack rule is invalid.");
    const rule = raw as Record<string, unknown>;
    exactKeys(rule, [
      "id",
      "title",
      "description",
      "severity",
      "category",
      "contains",
      "caseSensitive",
      "fileExtensions",
      "recommendation",
    ]);
    const id = text(rule.id, "rule id", 60);
    if (!/^[a-z0-9][a-z0-9-]*$/.test(id) || ruleIds.has(id))
      throw new Error("Rule pack rule id is invalid or duplicated.");
    ruleIds.add(id);
    const title = text(rule.title, "rule title", 120, 4);
    const description = text(rule.description, "rule description", 1000, 10);
    const contains = text(rule.contains, "literal", 500);
    const recommendation = text(
      rule.recommendation,
      "recommendation",
      1000,
      10,
    );
    if (
      typeof rule.severity !== "string" ||
      !severities.has(rule.severity as Severity)
    )
      throw new Error("Rule pack severity is invalid.");
    if (
      typeof rule.category !== "string" ||
      !categories.has(rule.category as Category)
    )
      throw new Error("Rule pack category is invalid.");
    if (
      rule.caseSensitive !== undefined &&
      typeof rule.caseSensitive !== "boolean"
    )
      throw new Error("Rule pack caseSensitive is invalid.");
    let fileExtensions: string[] | undefined;
    if (rule.fileExtensions !== undefined) {
      if (
        !Array.isArray(rule.fileExtensions) ||
        rule.fileExtensions.length > 20 ||
        rule.fileExtensions.some(
          (extension) =>
            typeof extension !== "string" ||
            !/^\.[a-z0-9]{1,10}$/.test(extension),
        ) ||
        new Set(rule.fileExtensions).size !== rule.fileExtensions.length
      )
        throw new Error("Rule pack fileExtensions is invalid.");
      fileExtensions = rule.fileExtensions as string[];
    }
    return {
      id,
      title,
      description,
      severity: rule.severity as Severity,
      category: rule.category as Category,
      contains,
      ...(rule.caseSensitive !== undefined
        ? { caseSensitive: rule.caseSensitive }
        : {}),
      ...(fileExtensions !== undefined ? { fileExtensions } : {}),
      recommendation,
    };
  });
  return {
    formatVersion: 1,
    packId,
    version,
    compatibility: { engineVersions: compatibility.engineVersions as string[] },
    rules,
  };
}

function digest(payload: RulePackPayload): string {
  return createHash("sha256").update(canonical(payload)).digest("hex");
}

function signingBytes(
  pack: Pick<SignedRulePack, "keyId" | "payload" | "hash">,
): Buffer {
  return Buffer.from(
    canonical({ keyId: pack.keyId, hash: pack.hash, payload: pack.payload }),
  );
}

function publicKey(input: KeyLike | string | Buffer): KeyObject {
  if (input instanceof KeyObject) {
    if (input.type !== "public")
      throw new Error("Rule pack verifier accepts public keys only.");
    return input;
  }
  const bytes = typeof input === "string" ? input : input.toString("utf8");
  if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(bytes))
    throw new Error("Rule pack verifier accepts public keys only.");
  const key = createPublicKey(input);
  if (key.type !== "public")
    throw new Error("Rule pack verifier accepts public keys only.");
  return key;
}

export function canonicalRulePackPayload(payload: RulePackPayload): string {
  return canonical(validatePayload(payload));
}

export function createSignedRulePack(
  payload: RulePackPayload,
  keyId: string,
  privateKey: KeyLike | string | Buffer,
): SignedRulePack {
  if (!/^[A-Za-z0-9._-]{1,100}$/.test(keyId))
    throw new Error("Rule pack keyId is invalid.");
  const checked = validatePayload(payload);
  const key =
    privateKey instanceof KeyObject ? privateKey : createPrivateKey(privateKey);
  if (key.asymmetricKeyType !== "ed25519")
    throw new Error("Rule pack signing key must be Ed25519.");
  const hash = digest(checked);
  const signature = sign(
    null,
    signingBytes({ keyId, payload: checked, hash }),
    key,
  ).toString("base64url");
  const signed = { keyId, payload: checked, hash, signature };
  if (Buffer.byteLength(canonical(signed), "utf8") > maxPackBytes)
    throw new Error("Rule pack exceeds the 1 MiB size limit.");
  return signed;
}

export function verifySignedRulePack(
  pack: SignedRulePack,
  trustedKeys: Record<string, KeyLike | string | Buffer>,
  engineVersion = ENGINE_VERSION,
): SignedRulePack {
  if (!pack || typeof pack !== "object" || Array.isArray(pack))
    throw new Error("A signed rule pack is required.");
  exactKeys(pack as unknown as Record<string, unknown>, [
    "keyId",
    "payload",
    "hash",
    "signature",
  ]);
  if (!/^[A-Za-z0-9._-]{1,100}$/.test(pack.keyId))
    throw new Error("Rule pack keyId is invalid.");
  if (
    typeof pack.hash !== "string" ||
    !/^[a-f0-9]{64}$/.test(pack.hash) ||
    typeof pack.signature !== "string" ||
    !/^[A-Za-z0-9_-]{86}$/.test(pack.signature)
  )
    throw new Error("Rule pack integrity fields are invalid.");
  if (
    !trustedKeys ||
    typeof trustedKeys !== "object" ||
    (Object.getPrototypeOf(trustedKeys) !== Object.prototype &&
      Object.getPrototypeOf(trustedKeys) !== null) ||
    !Object.hasOwn(trustedKeys, pack.keyId)
  )
    throw new Error("Rule pack signing key is not trusted.");
  const keyInput = trustedKeys[pack.keyId];
  if (!keyInput) throw new Error("Rule pack signing key is not trusted.");
  const key = publicKey(keyInput);
  if (key.asymmetricKeyType !== "ed25519")
    throw new Error("Rule pack verification key must be Ed25519.");
  const payload = validatePayload(pack.payload);
  const normalized = { keyId: pack.keyId, payload, hash: pack.hash };
  if (
    Buffer.byteLength(
      canonical({ ...normalized, signature: pack.signature }),
      "utf8",
    ) > maxPackBytes
  )
    throw new Error("Rule pack exceeds the 1 MiB size limit.");
  if (digest(payload) !== pack.hash)
    throw new Error("Rule pack content hash does not match.");
  if (
    Buffer.from(pack.signature, "base64url").toString("base64url") !==
      pack.signature ||
    !verify(
      null,
      signingBytes(normalized),
      key,
      Buffer.from(pack.signature, "base64url"),
    )
  )
    throw new Error("Rule pack signature is invalid.");
  if (
    !semver.test(engineVersion) ||
    !payload.compatibility.engineVersions.includes(engineVersion)
  )
    throw new Error("Rule pack is incompatible with this engine version.");
  return {
    keyId: pack.keyId,
    payload,
    hash: pack.hash,
    signature: pack.signature,
  };
}

function lineStarts(textValue: string): number[] {
  const starts = [0];
  for (let index = 0; index < textValue.length; index++)
    if (textValue.charCodeAt(index) === 10) starts.push(index + 1);
  return starts;
}

function location(
  starts: number[],
  index: number,
): { line: number; column: number } {
  let low = 0;
  let high = starts.length;
  while (low < high) {
    const middle = (low + high) >>> 1;
    if (starts[middle]! <= index) low = middle + 1;
    else high = middle;
  }
  const lineIndex = Math.max(0, low - 1);
  return { line: lineIndex + 1, column: index - starts[lineIndex]! + 1 };
}

function withinRoot(root: string, file: string): boolean {
  const relative = path.relative(root, file);
  return (
    relative !== "" &&
    relative !== ".." &&
    !relative.startsWith(`..${path.sep}`) &&
    !path.isAbsolute(relative)
  );
}

async function readBoundedFile(
  file: string,
  maximumBytes: number,
): Promise<Buffer | undefined> {
  const noFollow = process.platform === "win32" ? 0 : fsConstants.O_NOFOLLOW;
  const handle = await open(file, fsConstants.O_RDONLY | noFollow);
  try {
    const info = await handle.stat();
    if (!info.isFile() || info.size > maximumBytes) return undefined;
    const chunks: Buffer[] = [];
    let total = 0;
    let position = 0;
    while (total <= maximumBytes) {
      const buffer = Buffer.alloc(
        Math.min(64 * 1024, maximumBytes + 1 - total),
      );
      const { bytesRead } = await handle.read(
        buffer,
        0,
        buffer.byteLength,
        position,
      );
      if (bytesRead === 0) break;
      total += bytesRead;
      if (total > maximumBytes) return undefined;
      chunks.push(buffer.subarray(0, bytesRead));
      position += bytesRead;
    }
    return Buffer.concat(chunks, total);
  } finally {
    await handle.close();
  }
}

export async function applySignedRulePack(
  result: ScanResult,
  root: string,
  files: string[],
  signedPack: SignedRulePack,
  trustedKeys: Record<string, KeyLike | string | Buffer>,
): Promise<void> {
  const pack = verifySignedRulePack(signedPack, trustedKeys);
  const relativeRoot = await realpath(root);
  result.rulePacks ??= [];
  if (
    !result.rulePacks.some(
      (entry) =>
        entry.packId === pack.payload.packId &&
        entry.version === pack.payload.version,
    )
  )
    result.rulePacks.push({
      packId: pack.payload.packId,
      version: pack.payload.version,
      hash: pack.hash,
    });

  let processedFiles = 0;
  let sourceBytes = 0;
  const reportedMatchCaps = new Set<string>();
  for (const file of files) {
    if (processedFiles >= maxFiles || sourceBytes >= maxSourceBytes) {
      result.diagnostics.push({
        message: `Signed rule pack ${pack.payload.packId}@${pack.payload.version} reached its scan budget.`,
      });
      break;
    }
    if (result.findings.length >= maxFindings) {
      result.diagnostics.push({
        message: "Signed rule pack finding cap reached.",
      });
      break;
    }
    const absolute = path.resolve(
      relativeRoot,
      path.relative(relativeRoot, file),
    );
    if (!withinRoot(relativeRoot, absolute)) continue;
    let actualPath: string;
    let content: string;
    try {
      const info = await lstat(absolute);
      if (info.isSymbolicLink() || !info.isFile()) continue;
      if (
        info.size > 2 * 1024 * 1024 ||
        sourceBytes + info.size > maxSourceBytes
      )
        continue;
      actualPath = await realpath(absolute);
      if (!withinRoot(relativeRoot, actualPath)) continue;
      const currentPath = await realpath(actualPath);
      if (!withinRoot(relativeRoot, currentPath) || currentPath !== actualPath)
        continue;
      const bytes = await readBoundedFile(actualPath, 2 * 1024 * 1024);
      if (!bytes || sourceBytes + bytes.byteLength > maxSourceBytes) continue;
      content = bytes.toString("utf8");
      sourceBytes += bytes.byteLength;
      processedFiles++;
    } catch {
      continue;
    }
    const relative = path
      .relative(relativeRoot, actualPath)
      .replaceAll("\\", "/");
    const extension = path.extname(relative).toLowerCase();
    const starts = lineStarts(content);
    for (const rule of pack.payload.rules) {
      if (
        rule.fileExtensions?.length &&
        !rule.fileExtensions.includes(extension)
      )
        continue;
      const haystack =
        rule.caseSensitive === false ? content.toLowerCase() : content;
      const needle =
        rule.caseSensitive === false
          ? rule.contains.toLowerCase()
          : rule.contains;
      let from = 0;
      let matches = 0;
      while (
        matches < maxMatchesPerRuleFile &&
        result.findings.length < maxFindings
      ) {
        const index = haystack.indexOf(needle, from);
        if (index < 0) break;
        const point = location(starts, index);
        const ruleId = `REAPER-PACK-${pack.payload.packId.toUpperCase()}-${rule.id.toUpperCase()}`;
        const packFinding = finding(
          {
            ruleId,
            title: rule.title,
            description: rule.description,
            severity: rule.severity,
            confidence: "LOW",
            category: rule.category,
            file: relative,
            line: point.line,
            column: point.column,
            evidence: [
              `Signed data-only rule pack ${pack.payload.packId}@${pack.payload.version} matched a literal at this location.`,
              `Rule pack SHA-256: ${pack.hash}`,
            ],
            dataFlow: [],
            recommendation: rule.recommendation,
          },
          `pack:${pack.payload.packId}:${pack.payload.version}:${rule.id}:${point.line}:${point.column}`,
        );
        result.findings.push(packFinding);
        matches++;
        from = index + Math.max(1, needle.length);
      }
      if (
        matches === maxMatchesPerRuleFile &&
        !reportedMatchCaps.has(rule.id)
      ) {
        reportedMatchCaps.add(rule.id);
        result.diagnostics.push({
          message: `Signed rule pack ${pack.payload.packId}@${pack.payload.version} reached the per-file match cap for rule ${rule.id}.`,
        });
      }
    }
  }
}
