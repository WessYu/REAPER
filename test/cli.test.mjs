import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, rm, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
const run = (...args) =>
  spawnSync(process.execPath, ["dist/cli.js", ...args], { encoding: "utf8" });
test("version, help, invalid commands and flags", () => {
  assert.equal(run("--version").stdout, "0.1.0\n");
  assert.match(run("--help").stdout, /reaper scan/);
  assert.equal(run("verify").status, 2);
  assert.equal(run("scan", "--unknown").status, 2);
  assert.equal(run("scan", "--fail-on", "banana").status, 2);
});
test("E2E CLI gates vulnerable and secure applications", () => {
  const bad = run(
    "scan",
    "test/fixtures/vulnerable",
    "--format",
    "json",
    "--fail-on",
    "high",
  );
  assert.equal(bad.status, 1);
  assert.equal(JSON.parse(bad.stdout).findings.length, 3);
  const good = run(
    "scan",
    "test/fixtures/secure",
    "--format",
    "json",
    "--fail-on",
    "medium",
  );
  assert.equal(good.status, 0);
  assert.equal(JSON.parse(good.stdout).findings.length, 0);
});
test("report, baseline, diff and explain use real persisted evidence", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "reaper-cli-"));
  try {
    const a = path.join(root, "a.json"),
      b = path.join(root, "b.json"),
      base = path.join(root, "baseline.json");
    assert.equal(
      run("scan", "test/fixtures/vulnerable", "--format", "json", "--output", a)
        .status,
      0,
    );
    assert.equal(run("baseline", a, "--output", base).status, 0);
    assert.equal(
      run(
        "scan",
        "test/fixtures/vulnerable",
        "--baseline",
        base,
        "--fail-on",
        "info",
        "--format",
        "json",
        "--output",
        b,
      ).status,
      0,
    );
    assert.equal(JSON.parse(run("diff", a, b).stdout).added.length, 0);
    const data = JSON.parse(await readFile(a, "utf8"));
    assert.equal(
      JSON.parse(
        run("explain", data.findings[0].id, "--input", a, "--format", "json")
          .stdout,
      ).id,
      data.findings[0].id,
    );
    assert.equal(
      JSON.parse(run("report", a, "--format", "sarif").stdout).version,
      "2.1.0",
    );
    await writeFile(base, "{}");
    assert.equal(
      run("scan", "test/fixtures/secure", "--baseline", base).status,
      2,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
