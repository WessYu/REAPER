import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { execFile } from "node:child_process";

const execFileAsync = promisify(execFile);
const script = fileURLToPath(
  new URL("../scripts/artifact-hashes.mjs", import.meta.url),
);

test("artifact hash manifest detects post-generation package changes", async () => {
  const cwd = await mkdtemp(path.join(tmpdir(), "reaper-artifact-hash-"));
  try {
    await writeFile(
      path.join(cwd, "reaper.cdx.json"),
      '{"bomFormat":"CycloneDX"}\n',
    );
    await writeFile(
      path.join(cwd, "wess2001-reaper-0.2.0.tgz"),
      "package artifact",
    );
    await execFileAsync(process.execPath, [script, "write"], { cwd });
    const manifest = JSON.parse(
      await readFile(path.join(cwd, "package-artifact-hashes.json"), "utf8"),
    );
    assert.equal(manifest.algorithm, "sha256");
    assert.equal(manifest.artifacts.length, 2);
    await execFileAsync(process.execPath, [script, "verify"], { cwd });

    await writeFile(
      path.join(cwd, "wess2001-reaper-0.2.0.tgz"),
      "changed artifact",
    );
    await assert.rejects(
      execFileAsync(process.execPath, [script, "verify"], { cwd }),
      /Artifact integrity check failed/,
    );
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});
