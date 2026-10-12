import { AsyncLocalStorage } from "node:async_hooks";

interface TraceContext {
  traceId: string;
}

const storage = new AsyncLocalStorage<TraceContext>();

function header(
  headers:
    | Headers
    | Record<string, string | string[] | undefined>
    | undefined,
  name: string,
): string | undefined {
  if (!headers) return undefined;
  if (headers instanceof Headers) return headers.get(name) ?? undefined;
  const wanted = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== wanted) continue;
    if (Array.isArray(value)) return value[0];
    return value;
  }
  return undefined;
}

function traceIdFrom(
  headers:
    | Headers
    | Record<string, string | string[] | undefined>
    | undefined,
): string | undefined {
  const value = header(headers, "x-reaper-trace-id");
  return value &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      value,
    )
    ? value
    : undefined;
}

export function currentReaperTraceId(): string | undefined {
  return storage.getStore()?.traceId;
}

export function runWithReaperTrace<T>(
  headers:
    | Headers
    | Record<string, string | string[] | undefined>
    | undefined,
  fn: () => T,
): T {
  const traceId = traceIdFrom(headers);
  if (!traceId) return fn();
  return storage.run({ traceId }, fn);
}

export function reaperTraceMiddleware(
  request: {
    headers?: Record<string, string | string[] | undefined>;
  },
  _response: unknown,
  next: (error?: unknown) => void,
): void {
  const traceId = traceIdFrom(request.headers);
  if (!traceId) {
    next();
    return;
  }
  storage.run({ traceId }, () => next());
}
