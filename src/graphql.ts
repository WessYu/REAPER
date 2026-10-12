export interface GraphqlArgumentPlan {
  name: string;
  type: string;
  required: boolean;
}

export interface GraphqlFieldPlan {
  operation: "query" | "mutation" | "subscription";
  parentType: string;
  name: string;
  returnType: string;
  arguments: GraphqlArgumentPlan[];
  deprecated: boolean;
  mutationLike: boolean;
}

export interface GraphqlPlan {
  queryType?: string;
  mutationType?: string;
  subscriptionType?: string;
  fields: GraphqlFieldPlan[];
  counts: {
    queries: number;
    mutations: number;
    subscriptions: number;
    identifierArguments: number;
  };
}

function record(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function unwrapType(value: unknown): {
  text: string;
  required: boolean;
} {
  const current = record(value);
  if (!current) return { text: "Unknown", required: false };
  const kind = typeof current.kind === "string" ? current.kind : "UNKNOWN";
  if (kind === "NON_NULL") {
    const inner = unwrapType(current.ofType);
    return { text: `${inner.text}!`, required: true };
  }
  if (kind === "LIST") {
    const inner = unwrapType(current.ofType);
    return { text: `[${inner.text}]`, required: false };
  }
  return {
    text: typeof current.name === "string" ? current.name : kind,
    required: false,
  };
}

function rootName(
  schema: Record<string, unknown>,
  key: "queryType" | "mutationType" | "subscriptionType",
): string | undefined {
  const root = record(schema[key]);
  return typeof root?.name === "string" ? root.name : undefined;
}

function operationFields(
  types: unknown,
  parentType: string | undefined,
  operation: GraphqlFieldPlan["operation"],
): GraphqlFieldPlan[] {
  if (!parentType || !Array.isArray(types)) return [];
  const type = types.map(record).find((item) => item?.name === parentType);
  if (!type || !Array.isArray(type.fields)) return [];
  const fields: GraphqlFieldPlan[] = [];
  for (const raw of type.fields) {
    const field = record(raw);
    if (!field || typeof field.name !== "string") continue;
    const args: GraphqlArgumentPlan[] = [];
    for (const rawArg of Array.isArray(field.args) ? field.args : []) {
      const arg = record(rawArg);
      if (!arg || typeof arg.name !== "string") continue;
      const typeInfo = unwrapType(arg.type);
      args.push({
        name: arg.name,
        type: typeInfo.text,
        required: typeInfo.required,
      });
    }
    args.sort((a, b) => a.name.localeCompare(b.name));
    fields.push({
      operation,
      parentType,
      name: field.name,
      returnType: unwrapType(field.type).text,
      arguments: args,
      deprecated: field.isDeprecated === true,
      mutationLike: operation === "mutation",
    });
  }
  return fields.sort((a, b) => a.name.localeCompare(b.name));
}

export function planGraphql(document: unknown): GraphqlPlan {
  const root = record(document);
  if (!root) throw new Error("GraphQL introspection must be an object.");
  const data = record(root.data) ?? root;
  const schema = record(data.__schema);
  if (!schema)
    throw new Error("GraphQL introspection does not contain __schema.");
  const queryType = rootName(schema, "queryType");
  const mutationType = rootName(schema, "mutationType");
  const subscriptionType = rootName(schema, "subscriptionType");
  const fields = [
    ...operationFields(schema.types, queryType, "query"),
    ...operationFields(schema.types, mutationType, "mutation"),
    ...operationFields(schema.types, subscriptionType, "subscription"),
  ];
  const identifierArguments = fields.reduce(
    (count, field) =>
      count +
      field.arguments.filter((arg) =>
        /(?:^|_)(?:id|uuid|key|slug)$/i.test(arg.name),
      ).length,
    0,
  );
  return {
    queryType,
    mutationType,
    subscriptionType,
    fields,
    counts: {
      queries: fields.filter((field) => field.operation === "query").length,
      mutations: fields.filter((field) => field.operation === "mutation")
        .length,
      subscriptions: fields.filter(
        (field) => field.operation === "subscription",
      ).length,
      identifierArguments,
    },
  };
}
