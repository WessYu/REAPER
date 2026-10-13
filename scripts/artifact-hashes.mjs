import { createHash } from "node:crypto";
import { lstat, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";

const [mode, manifestPath = "package-artifact-hashes.json"] =
  process.argv.slice(2);

async function digest(file) {
  const info = await lstat(file);
  if (!info.isFile() || info.isSymbolicLink())
    throw new Error(`Artifact must be a regular file: ${file}`);
  const bytes = await readFile(file);
  return createHash("sha256").update(bytes).digest("hex");
}

if (mode === "write") {
  const entries = await readdir(".", { withFileTypes: true });
  const artifacts = [
    "reaper.cdx.json",
    ...entries
      .filter(
        (entry) =>
          entry.isFile() && /^wess2001-reaper-.*\.tgz$/.test(entry.name),
      )
      .map((entry) => entry.name),
  ].sort();
  if (artifacts.length < 2)
    throw new Error("Expected an SBOM and an npm package tarball.");
  const items = [];
  for (const file of artifacts)
    items.push({ file, sha256: await digest(file) });
  await writeFile(
    manifestPath,
    `${JSON.stringify({ version: 1, algorithm: "sha256", artifacts: items }, null, 2)}\n`,
    { flag: "wx", mode: 0o600 },
  );
} else if (mode === "verify") {
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  if (
    manifest?.version !== 1 ||
    manifest?.algorithm !== "sha256" ||
    !Array.isArray(manifest.artifacts) ||
    manifest.artifacts.length < 2
  )
    throw new Error("Artifact hash manifest is invalid.");
  for (const item of manifest.artifacts) {
    if (
      !item ||
      typeof item.file !== "string" ||
      path.basename(item.file) !== item.file ||
      !/^[a-f0-9]{64}$/.test(item.sha256)
    )
      throw new Error("Artifact hash manifest contains an invalid entry.");
    if ((await digest(item.file)) !== item.sha256)
      throw new Error(`Artifact integrity check failed: ${item.file}`);
  }
} else {
  throw new Error(
    "Usage: node scripts/artifact-hashes.mjs <write|verify> [manifest]",
  );
}
