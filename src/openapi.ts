export interface OpenApiParameterPlan {
  name: string;
  in: "path" | "query" | "header" | "cookie" | "unknown";
  required: boolean;
}

export interface OpenApiOperationPlan {
  method: string;
  path: string;
  operationId?: string;
  tags: string[];
  mutating: boolean;
  destructive: boolean;
  securityDeclared: boolean;
  parameters: OpenApiParameterPlan[];
  requestContentTypes: string[];
  responseStatuses: string[];
}

export interface OpenApiPlan {
  version: string;
  title?: string;
  operations: OpenApiOperationPlan[];
  counts: {
    total: number;
    mutating: number;
    destructive: number;
    securityDeclared: number;
  };
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function parameters(
  shared: unknown,
  operation: Record<string, unknown>,
): OpenApiParameterPlan[] {
  const values = [
    ...(Array.isArray(shared) ? shared : []),
    ...(Array.isArray(operation.parameters) ? operation.parameters : []),
  ];
  const seen = new Map<string, OpenApiParameterPlan>();
  for (const raw of values) {
    const value = object(raw);
    if (!value || typeof value.name !== "string") continue;
    const location = ["path", "query", "header", "cookie"].includes(
      String(value.in),
    )
      ? (String(value.in) as OpenApiParameterPlan["in"])
      : "unknown";
    const planned = {
      name: value.name,
      in: location,
      required: value.required === true || location === "path",
    };
    seen.set(`${planned.in}:${planned.name}`, planned);
  }
  return [...seen.values()].sort(
    (a, b) => a.in.localeCompare(b.in) || a.name.localeCompare(b.name),
  );
}

export function planOpenApi(document: unknown): OpenApiPlan {
  const root = object(document);
  if (!root) throw new Error("OpenAPI document must be an object.");
  if (typeof root.openapi !== "string" && typeof root.swagger !== "string")
    throw new Error("Document does not declare an OpenAPI/Swagger version.");
  const paths = object(root.paths);
  if (!paths) throw new Error("OpenAPI document does not contain paths.");
  const rootSecurityDeclared = Array.isArray(root.security);
  const methods = new Set([
    "get",
    "head",
    "options",
    "post",
    "put",
    "patch",
    "delete",
  ]);
  const operations: OpenApiOperationPlan[] = [];
  for (const [pathname, rawPath] of Object.entries(paths)) {
    if (!pathname.startsWith("/")) continue;
    const pathItem = object(rawPath);
    if (!pathItem) continue;
    for (const [rawMethod, rawOperation] of Object.entries(pathItem)) {
      const method = rawMethod.toLowerCase();
      if (!methods.has(method)) continue;
      const operation = object(rawOperation);
      if (!operation) continue;
      const requestBody = object(operation.requestBody);
      const requestContent = object(requestBody?.content);
      const responses = object(operation.responses);
      const securityDeclared =
        Array.isArray(operation.security) || rootSecurityDeclared;
      operations.push({
        method: method.toUpperCase(),
        path: pathname,
        operationId:
          typeof operation.operationId === "string"
            ? operation.operationId
            : undefined,
        tags: Array.isArray(operation.tags)
          ? operation.tags.filter(
              (tag): tag is string => typeof tag === "string",
            )
          : [],
        mutating: !["get", "head", "options"].includes(method),
        destructive: method === "delete",
        securityDeclared,
        parameters: parameters(pathItem.parameters, operation),
        requestContentTypes: requestContent
          ? Object.keys(requestContent).sort()
          : [],
        responseStatuses: responses ? Object.keys(responses).sort() : [],
      });
    }
  }
  operations.sort(
    (a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method),
  );
  const info = object(root.info);
  return {
    version: String(root.openapi ?? root.swagger),
    title: typeof info?.title === "string" ? info.title : undefined,
    operations,
    counts: {
      total: operations.length,
      mutating: operations.filter((item) => item.mutating).length,
      destructive: operations.filter((item) => item.destructive).length,
      securityDeclared: operations.filter((item) => item.securityDeclared)
        .length,
    },
  };
}
