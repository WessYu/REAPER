import { test } from "node:test";
import assert from "node:assert/strict";
import {
  assertRunnerIsolation,
  ProcessIsolationProvider,
} from "../dist/index.js";

test("standard process runner is explicit about missing sandbox capabilities", () => {
  const provider = new ProcessIsolationProvider();
  assert.equal(provider.capabilities.processIsolation, true);
  assert.equal(provider.capabilities.filesystemIsolation, false);
  assert.equal(provider.capabilities.networkIsolation, false);
  assert.equal(provider.capabilities.resourceLimits, false);
  assert.doesNotThrow(() => assertRunnerIsolation("standard", provider));
  assert.throws(
    () => assertRunnerIsolation("strict", provider),
    /requires filesystem isolation, network isolation and enforceable resource limits/,
  );
});

test("strict isolation never silently falls back when a provider lacks one capability", () => {
  const base = new ProcessIsolationProvider();
  for (const missing of [
    "filesystemIsolation",
    "networkIsolation",
    "resourceLimits",
  ]) {
    const provider = {
      name: `missing-${missing}`,
      capabilities: {
        processIsolation: true,
        filesystemIsolation: true,
        networkIsolation: true,
        resourceLimits: true,
        [missing]: false,
      },
      spawn(input) {
        return base.spawn(input);
      },
    };
    assert.throws(
      () => assertRunnerIsolation("strict", provider),
      /Strict runner mode requires/,
    );
  }
});
