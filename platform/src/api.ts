import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { authenticateApiKey, parseBearerHeader } from "./auth.js";
import { createPlatformPool } from "./db.js";
import { PlatformRepository } from "./repository.js";

const MAX_BODY_BYTES = 64 * 1024;

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required.`);
  return value;
}

async function jsonBody(
  request: IncomingMessage,
): Promise<Record<string, unknown>> {
  const contentType = request.headers["content-type"];
  if (!contentType?.toLowerCase().startsWith("application/json"))
    throw new Error("Content-Type must be application/json.");
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += buffer.length;
    if (total > MAX_BODY_BYTES) throw new Error("Request body exceeds 64 KiB.");
    chunks.push(buffer);
  }
  if (total === 0) return {};
  const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
    throw new Error("JSON request body must be an object.");
  return parsed as Record<string, unknown>;
}

function sendJson(
  response: ServerResponse,
  status: number,
  value: unknown,
): void {
  const body = JSON.stringify(value);
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  response.end(body);
}

function sendError(
  response: ServerResponse,
  status: number,
  message: string,
): void {
  sendJson(response, status, { error: message });
}

function routeId(pathname: string, prefix: string, suffix = ""): string | null {
  if (!pathname.startsWith(prefix) || !pathname.endsWith(suffix)) return null;
  const value = pathname.slice(
    prefix.length,
    suffix ? -suffix.length : undefined,
  );
  return value && !value.includes("/") ? value : null;
}

function clientError(message: string): boolean {
  return /(invalid|required|missing|must|not found|outside|belongs|role|format|content-type|exceeds|future)/i.test(
    message,
  );
}

export async function startApiServer(): Promise<
  ReturnType<typeof createServer>
> {
  const pool = createPlatformPool(required("REAPER_PLATFORM_DATABASE_URL"));
  const pepper = required("REAPER_PLATFORM_API_KEY_PEPPER");
  const repository = new PlatformRepository(pool, pepper);
  const dashboard = await readFile(
    fileURLToPath(new URL("../dashboard/index.html", import.meta.url)),
    "utf8",
  );

  const server = createServer(async (request, response) => {
    const method = request.method ?? "GET";
    const url = new URL(request.url ?? "/", "http://localhost");

    try {
      if (method === "GET" && url.pathname === "/health") {
        const probe = await pool.query("SELECT 1 AS ok");
        sendJson(response, 200, {
          status: probe.rows[0]?.ok === 1 ? "ok" : "degraded",
        });
        return;
      }

      if (
        method === "GET" &&
        (url.pathname === "/" || url.pathname === "/dashboard")
      ) {
        response.writeHead(200, {
          "content-type": "text/html; charset=utf-8",
          "content-security-policy":
            "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
          "x-content-type-options": "nosniff",
          "referrer-policy": "no-referrer",
          "cache-control": "no-store",
        });
        response.end(dashboard);
        return;
      }

      let context;
      try {
        const token = parseBearerHeader(
          Array.isArray(request.headers.authorization)
            ? request.headers.authorization[0]
            : request.headers.authorization,
        );
        context = await authenticateApiKey(pool, token, pepper);
      } catch {
        sendError(response, 401, "Authentication failed.");
        return;
      }

      if (method === "GET" && url.pathname === "/v1/me") {
        sendJson(response, 200, await repository.me(context));
        return;
      }

      if (method === "GET" && url.pathname === "/v1/projects") {
        sendJson(response, 200, {
          items: await repository.listProjects(context),
        });
        return;
      }
      if (method === "POST" && url.pathname === "/v1/projects") {
        const body = await jsonBody(request);
        sendJson(
          response,
          201,
          await repository.createProject(context, {
            name: body.name as string,
          }),
        );
        return;
      }

      if (method === "GET" && url.pathname === "/v1/assessments") {
        sendJson(response, 200, {
          items: await repository.listAssessments(context),
        });
        return;
      }
      if (method === "POST" && url.pathname === "/v1/assessments") {
        const body = await jsonBody(request);
        sendJson(
          response,
          201,
          await repository.createAssessment(context, {
            projectId: body.projectId as string,
            reference: body.reference as string,
          }),
        );
        return;
      }

      if (method === "GET" && url.pathname === "/v1/runs") {
        sendJson(response, 200, { items: await repository.listRuns(context) });
        return;
      }
      if (method === "POST" && url.pathname === "/v1/runs") {
        const body = await jsonBody(request);
        sendJson(
          response,
          202,
          await repository.createRun(context, body as never),
        );
        return;
      }

      const findingRun = routeId(url.pathname, "/v1/runs/", "/findings");
      if (method === "GET" && findingRun) {
        sendJson(response, 200, {
          items: await repository.listFindings(context, findingRun),
        });
        return;
      }

      const auditRun = routeId(url.pathname, "/v1/runs/", "/audit");
      if (method === "GET" && auditRun) {
        sendJson(response, 200, {
          items: await repository.listAudit(context, auditRun),
        });
        return;
      }

      const runId = routeId(url.pathname, "/v1/runs/");
      if (method === "GET" && runId) {
        sendJson(response, 200, await repository.getRun(context, runId));
        return;
      }

      if (method === "GET" && url.pathname === "/v1/api-keys") {
        sendJson(response, 200, {
          items: await repository.listApiKeys(context),
        });
        return;
      }
      if (method === "POST" && url.pathname === "/v1/api-keys") {
        const body = await jsonBody(request);
        sendJson(
          response,
          201,
          await repository.createApiKey(context, {
            principalId: body.principalId as string | undefined,
            name: body.name as string,
            expiresAt: (body.expiresAt as string | null | undefined) ?? null,
          }),
        );
        return;
      }

      const keyId = routeId(url.pathname, "/v1/api-keys/");
      if (method === "DELETE" && keyId) {
        const revoked = await repository.revokeApiKey(context, keyId);
        sendJson(response, revoked ? 200 : 404, { revoked });
        return;
      }

      sendError(response, 404, "Route not found.");
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Request failed.";
      sendError(
        response,
        clientError(message) ? 400 : 500,
        clientError(message) ? message : "Internal server error.",
      );
    }
  });

  server.on("close", () => {
    void pool.end();
  });

  const port = Number(process.env.REAPER_PLATFORM_PORT ?? 7338);
  const host = process.env.REAPER_PLATFORM_HOST ?? "127.0.0.1";
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535)
    throw new Error("REAPER_PLATFORM_PORT is invalid.");
  server.listen(port, host);
  return server;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  startApiServer()
    .then((server) => {
      const address = server.address();
      console.log(
        `REAPER Platform API listening on ${typeof address === "string" ? address : `${address?.address}:${address?.port}`}`,
      );
    })
    .catch((error: unknown) => {
      console.error(error instanceof Error ? error.message : error);
      process.exitCode = 2;
    });
}
