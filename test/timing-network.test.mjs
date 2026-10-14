import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { runLocalTimingSqliLab } from "../dist/index.js";

test("real loopback HTTP controls distinguish delayed and non-delayed lab endpoints", async () => {
  let requests = 0;
  let validCookies = true;
  const server = createServer((request, response) => {
    requests++;
    const parsed = new URL(request.url, "http://127.0.0.1");
    if (request.headers.cookie !== "PHPSESSID=local-session; security=low") {
      validCookies = false;
    }
    const delayed =
      parsed.pathname === "/vulnerable" &&
      parsed.searchParams.get("id") === "POSITIVE";
    setTimeout(() => {
      response.writeHead(200, { "content-type": "text/html" });
      response.end("<h1>SQL Injection</h1>");
    }, delayed ? 130 : 5);
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const target = `http://127.0.0.1:${address.port}`;
    const common = {
      phpSessionId: "local-session",
      samples: 3,
      timeoutMs: 1500,
      responseMarker: "SQL Injection",
      experiments: [
        {
          name: "controlled runtime contrast",
          positive: "POSITIVE",
          negative: "NEGATIVE",
          expectedDelayMs: 100,
        },
      ],
    };
    const vulnerable = await runLocalTimingSqliLab(
      target + "/vulnerable",
      common,
    );
    const secure = await runLocalTimingSqliLab(
      target + "/secure",
      common,
    );

    assert.equal(validCookies, true);
    assert.equal(requests, 18);
    assert.equal(vulnerable.confirmed, 1);
    assert.equal(vulnerable.experiments[0].confidence, "HIGH");
    assert.equal(secure.confirmed, 0);
    assert.equal(secure.conclusion, "NO_CONSISTENT_EVIDENCE");
  } finally {
    await new Promise((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }
});
