import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const hashes = fileURLToPath(
  new URL("../scripts/artifact-hashes.mjs", import.meta.url),
);
const validate = fileURLToPath(
  new URL("../scripts/validate-release-evidence.mjs", import.meta.url),
);

test("release evidence validator fails closed when expected artifacts are missing or modified", async () => {
  const cwd = await mkdtemp(path.join(tmpdir(), "reaper-release-evidence-"));
  try {
    await writeFile(
      path.join(cwd, "reaper.cdx.json"),
      JSON.stringify({
        bomFormat: "CycloneDX",
        components: [{ type: "library", name: "reaper" }],
      }),
    );
    await writeFile(
      path.join(cwd, "wess2001-reaper-0.2.0.tgz"),
      "synthetic package",
    );
    await execFileAsync(process.execPath, [hashes, "write"], { cwd });
    await execFileAsync(process.execPath, [validate], { cwd });

    await writeFile(
      path.join(cwd, "wess2001-reaper-0.2.0.tgz"),
      "tampered package",
    );
    await assert.rejects(
      execFileAsync(process.execPath, [validate], { cwd }),
      /digest mismatch/,
    );
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});
