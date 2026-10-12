import { test } from "node:test";
import assert from "node:assert/strict";
import { createCallbackCollector } from "../dist/index.js";

test("loopback callback collector issues unguessable canaries and records bounded metadata", async () => {
  const collector = await createCallbackCollector();
  try {
    const issued = collector.issue("synthetic SSRF canary");
    assert.match(issued.url, /^http:\/\/127\.0\.0\.1:/);
    const waiting = collector.wait(issued.token, 1000);
    const response = await fetch(issued.url, {
      headers: {
        "user-agent": "reaper-test",
        authorization: "Bearer should-not-be-captured",
        cookie: "sid=should-not-be-captured",
      },
    });
    assert.equal(response.status, 204);
    const event = await waiting;
    assert.equal(event.label, "synthetic SSRF canary");
    assert.equal(event.userAgent, "reaper-test");
    assert.ok(!JSON.stringify(event).includes("should-not-be-captured"));
    assert.equal(collector.events(issued.token).length, 1);
  } finally {
    collector.close();
    await collector.closed;
  }
});

test("callback collector refuses unknown tokens and non-safe inbound methods", async () => {
  const collector = await createCallbackCollector();
  try {
    assert.equal((await fetch(`${collector.origin}/c/missing`)).status, 404);
    const issued = collector.issue("method");
    const response = await fetch(issued.url, { method: "DELETE" });
    assert.equal(response.status, 405);
    assert.equal(collector.events(issued.token).length, 0);
  } finally {
    collector.close();
    await collector.closed;
  }
});
