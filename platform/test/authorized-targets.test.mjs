import test from "node:test";
import assert from "node:assert/strict";
import { requireOperatorAuthorizedOrigin } from "../dist/authorized-targets.js";

test("commercial dispatch accepts an explicitly approved HTTPS origin", () => {
  assert.doesNotThrow(() =>
    requireOperatorAuthorizedOrigin(
      "https://preview.example.com",
      JSON.stringify(["https://preview.example.com"]),
    ),
  );
});

test("commercial dispatch rejects an absent or forged authorization list", () => {
  const candidate = "https://attacker.example.net";
  for (const entries of [
    undefined,
    "[]",
    "not-json",
    JSON.stringify(["https://preview.example.com"]),
    JSON.stringify(["https://preview.example.com/path"]),
    JSON.stringify(["https://localhost"]),
    JSON.stringify(["http://preview.example.com"]),
  ]) {
    assert.throws(() => requireOperatorAuthorizedOrigin(candidate, entries));
  }
});

test("commercial dispatch checks exact origin and rejects duplicates", () => {
  const configured = JSON.stringify(["https://preview.example.com"]);
  for (const target of [
    "https://preview.example.com.evil.com",
    "https://preview.example.com:8443",
    "https://127.0.0.1",
    "http://preview.example.com",
    "https://preview.example.com/path",
    "https://PREVIEW.example.com",
  ]) {
    assert.throws(() => requireOperatorAuthorizedOrigin(target, configured));
  }
  assert.throws(() =>
    requireOperatorAuthorizedOrigin(
      "https://preview.example.com",
      JSON.stringify([
        "https://preview.example.com",
        "https://preview.example.com",
      ]),
    ),
  );
});
