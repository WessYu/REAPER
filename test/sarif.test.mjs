import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import Ajv from "ajv-draft-04";
import addFormats from "ajv-formats";
import { scan, report } from "../dist/index.js";
test("SARIF 2.1.0 conforms to the vendored OASIS schema", async () => {
  const schema = JSON.parse(
    await readFile(
      new URL("./schema/sarif-2.1.0.json", import.meta.url),
      "utf8",
    ),
  );
  const ajv = new Ajv({ strict: false, allErrors: true });
  addFormats(ajv);
  const validate = ajv.compile(schema);
  for (const root of ["test/fixtures/vulnerable", "test/fixtures/secure"]) {
    const value = JSON.parse(report(await scan({ root }), "sarif"));
    assert.equal(validate(value), true, JSON.stringify(validate.errors));
  }
});
