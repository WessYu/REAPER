import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const read = (path) => readFile(new URL(`../${path}`, import.meta.url), "utf8");

test("Cloud Run mounts an independent runner-only trust secret", async () => {
  const terraform = await read("infra/gcp/main.tf");
  const entry = await read("platform/src/cloud-run-entry.ts");
  const dispatcher = await read("platform/src/cloud-dispatcher.ts");
  const invocation = await read("platform/src/cloud-run-job.ts");
  assert.match(
    terraform,
    /resource "google_secret_manager_secret" "runner_trusted_scope_keys"/,
  );
  assert.match(
    terraform,
    /resource "google_secret_manager_secret_iam_member" "runner_trust"/,
  );
  assert.match(terraform, /name = "runner-trust"/);
  assert.match(terraform, /mount_path = "\/var\/run\/reaper-trust"/);
  assert.match(
    entry,
    /readFile\([\s\S]*"\/var\/run\/reaper-trust\/trusted-scope-keys\.json"/,
  );
  assert.doesNotMatch(dispatcher, /trustedScopeKeys:/);
  assert.doesNotMatch(invocation, /REAPER_RUNNER_TRUSTED_SCOPE_KEYS_JSON/);
});
