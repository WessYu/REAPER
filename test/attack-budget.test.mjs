import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { once } from "node:events";
import { attack } from "../dist/index.js";

test("mutation budget stops stateful scenarios before excessive side effects", async () => {
  let mutations = 0;
  const server = http.createServer((req, res) => {
    if (req.method === "POST") {
      mutations++;
      res.setHeader("content-type", "application/json");
      res.statusCode = 201;
      res.end(JSON.stringify({ id: `r-${mutations}` }));
      return;
    }
    res.statusCode = 403;
    res.end();
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  const origin = `http://127.0.0.1:${address.port}`;
  try {
    const result = await attack(origin, {
      scope: { authorized: true, environment: "local" },
      allowMutations: true,
      maxMutationRequests: 1,
      identities: { a: {}, b: {} },
      scenarios: [
        {
          name: "one",
          kind: "bola",
          attackerIdentity: "a",
          ownerIdentity: "b",
          setup: [
            {
              name: "create one",
              path: "/api/resources",
              method: "POST",
              capture: { RESOURCE_ID: "id" },
            },
          ],
          attack: { name: "probe one", path: "/api/resources/{{RESOURCE_ID}}" },
        },
        {
          name: "two",
          kind: "bola",
          attackerIdentity: "a",
          ownerIdentity: "b",
          setup: [
            {
              name: "create two",
              path: "/api/resources",
              method: "POST",
              capture: { RESOURCE_ID: "id" },
            },
          ],
          attack: { name: "probe two", path: "/api/resources/{{RESOURCE_ID}}" },
        },
      ],
    });
    assert.equal(mutations, 1);
    assert.equal(result.attack.mutationCount, 2);
    assert.ok(
      result.diagnostics.some((item) =>
        /mutation budget exceeded/.test(item.message),
      ),
    );
  } finally {
    server.close();
    await once(server, "close");
  }
});
