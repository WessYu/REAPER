import { randomUUID } from "node:crypto";
import http from "node:http";

export interface CallbackEvent {
  token: string;
  label: string;
  method: string;
  path: string;
  userAgent?: string;
  contentType?: string;
  observedAt: string;
}

export interface CallbackCollector {
  origin: string;
  issue(label: string): { token: string; url: string };
  events(token?: string): CallbackEvent[];
  wait(token: string, timeoutMs?: number): Promise<CallbackEvent | undefined>;
  close(): void;
  closed: Promise<void>;
}

export async function createCallbackCollector(
  options: { port?: number } = {},
): Promise<CallbackCollector> {
  const labels = new Map<string, string>();
  const observed: CallbackEvent[] = [];
  const waiters = new Map<
    string,
    Array<(event: CallbackEvent | undefined) => void>
  >();

  const server = http.createServer((req, res) => {
    res.setHeader("cache-control", "no-store");
    res.setHeader("x-content-type-options", "nosniff");
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    const match = url.pathname.match(/^\/c\/([A-Za-z0-9-]+)$/);
    if (!match) {
      res.statusCode = 404;
      res.end("Not found\n");
      return;
    }
    const token = match[1]!;
    const label = labels.get(token);
    if (!label) {
      res.statusCode = 404;
      res.end("Unknown callback\n");
      return;
    }
    if (!["GET", "HEAD", "POST"].includes(req.method ?? "")) {
      res.statusCode = 405;
      res.setHeader("allow", "GET, HEAD, POST");
      res.end();
      return;
    }

    const event: CallbackEvent = {
      token,
      label,
      method: req.method ?? "GET",
      path: url.pathname,
      userAgent: req.headers["user-agent"],
      contentType: req.headers["content-type"],
      observedAt: new Date().toISOString(),
    };
    observed.push(event);
    for (const resolve of waiters.get(token) ?? []) resolve(event);
    waiters.delete(token);
    req.resume();
    res.statusCode = 204;
    res.end();
  });

  const port = options.port ?? 0;
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string")
    throw new Error("Callback collector did not bind.");
  const origin = `http://127.0.0.1:${address.port}`;
  const closed = new Promise<void>((resolve) => server.once("close", resolve));

  return {
    origin,
    issue(label: string) {
      if (!label.trim()) throw new Error("Callback label must be non-empty.");
      const token = randomUUID();
      labels.set(token, label.trim());
      return { token, url: `${origin}/c/${token}` };
    },
    events(token?: string) {
      return observed
        .filter((event) => token === undefined || event.token === token)
        .map((event) => ({ ...event }));
    },
    wait(token: string, timeoutMs = 5000) {
      const existing = observed.find((event) => event.token === token);
      if (existing) return Promise.resolve({ ...existing });
      if (!labels.has(token))
        throw new Error("Unknown callback token.");
      if (
        !Number.isSafeInteger(timeoutMs) ||
        timeoutMs < 1 ||
        timeoutMs > 30000
      )
        throw new Error("Callback timeout must be between 1 and 30000 ms.");
      return new Promise<CallbackEvent | undefined>((resolve) => {
        const timer = setTimeout(() => {
          const current = waiters.get(token) ?? [];
          waiters.set(
            token,
            current.filter((candidate) => candidate !== done),
          );
          resolve(undefined);
        }, timeoutMs);
        const done = (event: CallbackEvent | undefined) => {
          clearTimeout(timer);
          resolve(event ? { ...event } : undefined);
        };
        waiters.set(token, [...(waiters.get(token) ?? []), done]);
      });
    },
    close() {
      server.close();
      for (const pending of waiters.values())
        for (const resolve of pending) resolve(undefined);
      waiters.clear();
    },
    closed,
  };
}
