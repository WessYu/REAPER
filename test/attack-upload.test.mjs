import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { once } from "node:events";
import { attack, validateAttackConfig } from "../dist/index.js";

test("synthetic multipart scenarios stay bounded and never read local files", async () => {
  let seenType = "";
  let seenBody = "";
  const server = http.createServer((req, res) => {
    seenType = String(req.headers["content-type"] ?? "");
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      seenBody = Buffer.concat(chunks).toString("utf8");
      res.statusCode = 403;
      res.end();
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("No port.");
  const origin = `http://127.0.0.1:${address.port}`;

  process.env.REAPER_UPLOAD_CONTENT = "synthetic-file-content";
  try {
    const result = await attack(origin, {
      scope: { authorized: true, environment: "local" },
      allowMutations: true,
      maxUploadBytes: 1024,
      identities: { userA: {} },
      scenarios: [
        {
          name: "upload must be denied",
          kind: "authorization",
          attackerIdentity: "userA",
          attack: {
            name: "synthetic upload",
            path: "/api/uploads",
            method: "POST",
            multipart: {
              fields: { purpose: "avatar" },
              files: [
                {
                  field: "file",
                  filename: "reaper.txt",
                  content: "$env:REAPER_UPLOAD_CONTENT",
                  contentType: "text/plain",
                },
              ],
            },
            expectStatus: 403,
          },
        },
      ],
    });
    assert.equal(result.findings.length, 0);
    assert.match(seenType, /^multipart\/form-data; boundary=/);
    assert.match(seenBody, /synthetic-file-content/);
    assert.match(seenBody, /filename="reaper.txt"/);
    assert.ok(!JSON.stringify(result).includes("synthetic-file-content"));
  } finally {
    delete process.env.REAPER_UPLOAD_CONTENT;
    server.close();
    await once(server, "close");
  }
});

test("multipart config rejects local-path filenames and runtime enforces byte budget", async () => {
  assert.throws(
    () =>
      validateAttackConfig({
        scope: { authorized: true, environment: "local" },
        allowMutations: true,
        identities: { userA: {} },
        scenarios: [
          {
            name: "bad filename",
            kind: "authorization",
            attackerIdentity: "userA",
            attack: {
              name: "upload",
              path: "/api/uploads",
              method: "POST",
              multipart: {
                files: [
                  {
                    field: "file",
                    filename: "../secret.txt",
                    content: "x",
                  },
                ],
              },
            },
          },
        ],
      }),
    /filename/,
  );

  const server = http.createServer((_req, res) => {
    res.statusCode = 403;
    res.end();
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("No port.");
  try {
    const result = await attack(`http://127.0.0.1:${address.port}`, {
      scope: { authorized: true, environment: "local" },
      allowMutations: true,
      maxUploadBytes: 8,
      identities: { userA: {} },
      scenarios: [
        {
          name: "oversized upload",
          kind: "authorization",
          attackerIdentity: "userA",
          attack: {
            name: "upload",
            path: "/api/uploads",
            method: "POST",
            multipart: {
              files: [
                {
                  field: "file",
                  filename: "x.txt",
                  content: "0123456789",
                },
              ],
            },
          },
        },
      ],
    });
    assert.equal(result.findings.length, 0);
    assert.ok(
      result.diagnostics.some((item) => /maxUploadBytes/.test(item.message)),
    );
  } finally {
    server.close();
    await once(server, "close");
  }
});
