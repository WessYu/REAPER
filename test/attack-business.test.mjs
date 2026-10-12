import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { once } from "node:events";
import { attack } from "../dist/index.js";

test("business scenarios confirm bounded JSON invariant violations without retaining response data", async () => {
  const server = http.createServer((_req, res) => {
    res.setHeader("content-type", "application/json");
    res.statusCode = 200;
    res.end(
      JSON.stringify({
        approved: true,
        account: { role: "user" },
        internalSecret: "must-not-enter-report",
      }),
    );
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("No port.");
  try {
    const result = await attack(`http://127.0.0.1:${address.port}`, {
      scope: { authorized: true, environment: "local" },
      identities: { user: {} },
      scenarios: [
        {
          name: "approval invariant",
          kind: "business",
          attackerIdentity: "user",
          attack: {
            name: "read operation state",
            path: "/api/operation",
          },
          expect: {
            statuses: [200],
            json: { approved: false, "account.role": "user" },
            absentJsonPaths: ["internalSecret"],
          },
        },
      ],
    });
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].ruleId, "REAPER-ATTACK-008");
    assert.match(result.findings[0].evidence.join("\n"), /JSON response/);
    assert.ok(!JSON.stringify(result).includes("must-not-enter-report"));
  } finally {
    server.close();
    await once(server, "close");
  }
});

test("business JSON invariants pass when configured state is observed", async () => {
  const server = http.createServer((_req, res) => {
    res.setHeader("content-type", "application/json");
    res.statusCode = 200;
    res.end(JSON.stringify({ approved: false, account: { role: "user" } }));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("No port.");
  try {
    const result = await attack(`http://127.0.0.1:${address.port}`, {
      scope: { authorized: true, environment: "local" },
      identities: { user: {} },
      scenarios: [
        {
          name: "approval invariant",
          kind: "business",
          attackerIdentity: "user",
          attack: { name: "read state", path: "/api/operation" },
          expect: {
            statuses: [200],
            json: { approved: false, "account.role": "user" },
            absentJsonPaths: ["internalSecret"],
          },
        },
      ],
    });
    assert.equal(result.findings.length, 0);
    assert.equal(result.attack.scenarios[0].status, "passed");
  } finally {
    server.close();
    await once(server, "close");
  }
});
