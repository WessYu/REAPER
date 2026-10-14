import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const dashboards = [
  new URL("../dashboard/index.html", import.meta.url),
  new URL("../../supabase/functions/reaper-platform/index.ts", import.meta.url),
];

test("platform dashboards do not persist API credentials to web storage", async () => {
  for (const file of dashboards) {
    const source = await readFile(file, "utf8");
    assert.doesNotMatch(source, /sessionStorage|localStorage/);
    assert.match(source, /id="disconnect"/);
    assert.match(source, /token=""/);
  }
});

test("platform dashboards only export completed workspace-authenticated reports", async () => {
  for (const file of dashboards) {
    const source = await readFile(file, "utf8");
    assert.match(source, /exportReport/);
    assert.match(source, /encodeURIComponent\(run\.id\)/);
    assert.match(source, /detail\.status\s*!==\s*"COMPLETED"/);
    assert.match(source, /URL\.createObjectURL/);
    assert.match(source, /button\.disabled\s*=\s*run\.status\s*!==\s*"COMPLETED"|b\.disabled=run\.status!=="COMPLETED"/);
  }
});
