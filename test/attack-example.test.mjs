import { test } from "node:test";
import assert from "node:assert/strict";
import { readConfig } from "../dist/index.js";

test("documented active-security example remains valid literal configuration", async () => {
  const config = await readConfig("examples/reaper.attack.config.ts");
  assert.equal(config.attack.scope.environment, "staging");
  assert.equal(config.attack.scenarios.length, 2);
  assert.equal(config.attack.identities.admin.privilegeLevel, 90);
});
