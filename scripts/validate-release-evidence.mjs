import { createHash } from "node:crypto";
import { readFile, readdir, stat } from "node:fs/promises";
import path from "node:path";

function fail(message) {
  throw new Error(`Release evidence validation failed: ${message}`);
}

async function sha256(file) {
  return createHash("sha256").update(await readFile(file)).digest("hex");
}

const cwd = process.cwd();
const names = await readdir(cwd);
const packages = names
  .filter((name) => /^wess2001-reaper-.*\.tgz$/.test(name))
  .sort();
if (packages.length < 1) fail("npm package artifact is missing.");

const sbomPath = path.join(cwd, "reaper.cdx.json");
const hashesPath = path.join(cwd, "package-artifact-hashes.json");
for (const file of [sbomPath, hashesPath]) {
  let info;
  try {
    info = await stat(file);
  } catch {
    fail(`${path.basename(file)} is missing.`);
  }
  if (!info.isFile() || info.size < 2 || info.size > 20 * 1024 * 1024)
    fail(`${path.basename(file)} has an invalid size or type.`);
}

let sbom;
try {
  sbom = JSON.parse(await readFile(sbomPath, "utf8"));
} catch {
  fail("SBOM is not valid JSON.");
}
if (
  sbom?.bomFormat !== "CycloneDX" ||
  !Array.isArray(sbom.components) ||
  sbom.components.length < 1
)
  fail("CycloneDX SBOM is incomplete.");

let manifest;
try {
  manifest = JSON.parse(await readFile(hashesPath, "utf8"));
} catch {
  fail("artifact hash manifest is not valid JSON.");
}
if (
  manifest?.algorithm !== "sha256" ||
  !Array.isArray(manifest.artifacts) ||
  manifest.artifacts.length < 2
)
  fail("artifact hash manifest is incomplete.");

const entries = new Map();
for (const artifact of manifest.artifacts) {
  if (
    !artifact ||
    typeof artifact !== "object" ||
    typeof artifact.file !== "string" ||
    !/^[A-Za-z0-9._-]+$/.test(artifact.file) ||
    typeof artifact.sha256 !== "string" ||
    !/^[a-f0-9]{64}$/.test(artifact.sha256) ||
    entries.has(artifact.file)
  )
    fail("artifact hash manifest contains an invalid entry.");
  entries.set(artifact.file, artifact.sha256);
}

if (!entries.has("reaper.cdx.json"))
  fail("hash manifest does not include the SBOM.");
for (const packageName of packages)
  if (!entries.has(packageName))
    fail(`hash manifest does not include ${packageName}.`);

for (const [file, expected] of entries) {
  const fullPath = path.join(cwd, file);
  let actual;
  try {
    actual = await sha256(fullPath);
  } catch {
    fail(`manifest artifact ${file} is missing.`);
  }
  if (actual !== expected)
    fail(`manifest digest mismatch for ${file}.`);
}

process.stdout.write(
  `Release evidence ready: ${packages.length} package artifact(s), CycloneDX SBOM and verified SHA-256 manifest.\n`,
);
