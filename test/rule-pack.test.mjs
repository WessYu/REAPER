import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  ENGINE_VERSION,
  createSignedRulePack,
  report,
  scan,
  verifySignedRulePack,
} from "../dist/index.js";

function payload() {
  return {
    formatVersion: 1,
    packId: "example-data-pack",
    version: "1.0.0",
    compatibility: { engineVersions: [ENGINE_VERSION] },
    rules: [
      {
        id: "dangerous-query-builder",
        title: "Untrusted text reaches a query builder",
        description:
          "The configured unsafe query marker appears in source and needs review.",
        severity: "HIGH",
        category: "SQL Safety",
        contains: "dangerousRawQuery",
        fileExtensions: [".ts"],
        recommendation:
          "Use a parameterized query API and keep user values outside SQL text.",
      },
    ],
  };
}

test("signed data-only rule pack verifies and adds bounded literal findings", async () => {
  const keys = generateKeyPairSync("ed25519");
  const pack = createSignedRulePack(
    payload(),
    "rulepack-key-1",
    keys.privateKey,
  );
  const verified = verifySignedRulePack(pack, {
    "rulepack-key-1": keys.publicKey,
  });
  assert.equal(verified.hash, pack.hash);

  const root = await mkdtemp(path.join(tmpdir(), "reaper-rule-pack-"));
  try {
    await mkdir(path.join(root, "src"));
    await writeFile(
      path.join(root, "src", "route.ts"),
      'const query = "dangerousRawQuery";\nexport function run() { return query; }\n',
    );
    const result = await scan({
      root,
      rulePack: pack,
      trustedRulePackKeys: { "rulepack-key-1": keys.publicKey },
    });
    const findings = result.findings.filter((finding) =>
      finding.ruleId.startsWith("REAPER-PACK-EXAMPLE-DATA-PACK-"),
    );
    assert.equal(findings.length, 1);
    assert.equal(findings[0].file, "src/route.ts");
    assert.equal(findings[0].line, 1);
    assert.equal(findings[0].confidence, "LOW");
    assert.deepEqual(result.rulePacks, [
      { packId: "example-data-pack", version: "1.0.0", hash: pack.hash },
    ]);
    assert.ok(report(result, "json").includes(pack.hash));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("signed rule pack rejects tampering, untrusted keys and incompatible engines", () => {
  const keys = generateKeyPairSync("ed25519");
  const otherKeys = generateKeyPairSync("ed25519");
  const signed = createSignedRulePack(
    payload(),
    "rulepack-key-1",
    keys.privateKey,
  );
  assert.throws(
    () => verifySignedRulePack(signed, { "rulepack-key-1": keys.privateKey }),
    /public keys only/,
  );
  const changedRule = structuredClone(signed);
  changedRule.payload.rules[0].contains = "otherText";
  assert.throws(
    () =>
      verifySignedRulePack(changedRule, { "rulepack-key-1": keys.publicKey }),
    /hash does not match/,
  );
  assert.throws(
    () =>
      verifySignedRulePack(signed, { "rulepack-key-1": otherKeys.publicKey }),
    /signature is invalid/,
  );
  assert.throws(
    () =>
      verifySignedRulePack(
        signed,
        { "rulepack-key-1": keys.publicKey },
        "9.9.9",
      ),
    /incompatible/,
  );
});

test("rule pack data cannot declare executable callbacks or regex behavior", () => {
  const keys = generateKeyPairSync("ed25519");
  const executable = payload();
  executable.rules[0].run = "process.exit(1)";
  assert.throws(
    () => createSignedRulePack(executable, "rulepack-key-1", keys.privateKey),
    /unsupported field/,
  );
  const unboundedText = payload();
  unboundedText.rules[0].contains = "x".repeat(501);
  assert.throws(
    () =>
      createSignedRulePack(unboundedText, "rulepack-key-1", keys.privateKey),
    /literal is invalid/,
  );
  const regexField = payload();
  regexField.rules[0].pattern = "(a+)+$";
  assert.throws(
    () => createSignedRulePack(regexField, "rulepack-key-1", keys.privateKey),
    /unsupported field/,
  );
  const logInjection = payload();
  logInjection.rules[0].title = "Review this\nforged entry";
  assert.throws(
    () => createSignedRulePack(logInjection, "rulepack-key-1", keys.privateKey),
    /rule title is invalid/,
  );
});

test("scan requires trusted rule-pack keys and does not report unmatched literals", async () => {
  const keys = generateKeyPairSync("ed25519");
  const pack = createSignedRulePack(
    payload(),
    "rulepack-key-1",
    keys.privateKey,
  );
  const root = await mkdtemp(path.join(tmpdir(), "reaper-rule-pack-secure-"));
  try {
    await writeFile(path.join(root, "secure.ts"), 'const query = "safe";\n');
    await assert.rejects(
      scan({ root, rulePack: pack }),
      /both a pack and trusted keys/,
    );
    const result = await scan({
      root,
      rulePack: pack,
      trustedRulePackKeys: { "rulepack-key-1": keys.publicKey },
    });
    assert.equal(
      result.findings.some((finding) =>
        finding.ruleId.startsWith("REAPER-PACK-"),
      ),
      false,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
