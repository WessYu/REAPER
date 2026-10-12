import { test } from "node:test";
import assert from "node:assert/strict";
import { planGraphql } from "../dist/index.js";

test("GraphQL planner models query mutation and identifier-bearing fields", () => {
  const result = planGraphql({
    data: {
      __schema: {
        queryType: { name: "Query" },
        mutationType: { name: "Mutation" },
        subscriptionType: null,
        types: [
          {
            kind: "OBJECT",
            name: "Query",
            fields: [
              {
                name: "order",
                args: [
                  {
                    name: "id",
                    type: {
                      kind: "NON_NULL",
                      ofType: { kind: "SCALAR", name: "ID" },
                    },
                  },
                ],
                type: { kind: "OBJECT", name: "Order" },
                isDeprecated: false,
              },
            ],
          },
          {
            kind: "OBJECT",
            name: "Mutation",
            fields: [
              {
                name: "deleteOrder",
                args: [
                  {
                    name: "id",
                    type: { kind: "SCALAR", name: "ID" },
                  },
                ],
                type: { kind: "SCALAR", name: "Boolean" },
                isDeprecated: false,
              },
            ],
          },
        ],
      },
    },
  });
  assert.equal(result.counts.queries, 1);
  assert.equal(result.counts.mutations, 1);
  assert.equal(result.counts.identifierArguments, 2);
  assert.equal(result.fields[0].arguments[0].type, "ID!");
  assert.equal(
    result.fields.find((field) => field.name === "deleteOrder").mutationLike,
    true,
  );
});

test("GraphQL planner rejects non-introspection JSON", () => {
  assert.throws(() => planGraphql({ data: {} }), /__schema/);
});
