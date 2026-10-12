import { test } from "node:test";
import assert from "node:assert/strict";
import { planOpenApi } from "../dist/index.js";

test("OpenAPI planner models read and mutation surface without sending requests", () => {
  const plan = planOpenApi({
    openapi: "3.1.0",
    info: { title: "Orders API", version: "1" },
    security: [{ bearerAuth: [] }],
    paths: {
      "/orders/{id}": {
        parameters: [
          {
            name: "id",
            in: "path",
            required: true,
            schema: { type: "string" },
          },
        ],
        get: {
          operationId: "getOrder",
          responses: { 200: {}, 404: {} },
        },
        delete: {
          operationId: "deleteOrder",
          responses: { 204: {}, 404: {} },
        },
      },
      "/orders": {
        post: {
          tags: ["orders"],
          requestBody: {
            content: {
              "application/json": {},
              "multipart/form-data": {},
            },
          },
          responses: { 201: {} },
        },
      },
    },
  });
  assert.equal(plan.title, "Orders API");
  assert.equal(plan.counts.total, 3);
  assert.equal(plan.counts.mutating, 2);
  assert.equal(plan.counts.destructive, 1);
  assert.equal(plan.counts.securityDeclared, 3);
  const get = plan.operations.find(
    (item) => item.method === "GET" && item.path === "/orders/{id}",
  );
  assert.equal(get.parameters[0].name, "id");
  assert.equal(get.parameters[0].required, true);
  const post = plan.operations.find((item) => item.method === "POST");
  assert.deepEqual(post.requestContentTypes, [
    "application/json",
    "multipart/form-data",
  ]);
});

test("OpenAPI planner rejects unrelated JSON", () => {
  assert.throws(() => planOpenApi({ paths: {} }), /version/);
});
