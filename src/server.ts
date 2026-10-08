import http from "node:http";
import { scan } from "./scan.js";
import { renderDashboard } from "./dashboard.js";
import type { ScanResult } from "./model.js";

export async function createReaperServer(options: {
  root: string;
  configFile?: string;
  port?: number;
}): Promise<{ server: http.Server; port: number }> {
  let latest: ScanResult | undefined;
  let running: Promise<ScanResult> | undefined;
  const execute = async () => {
    if (!running)
      running = scan({
        root: options.root,
        configFile: options.configFile,
      }).finally(() => {
        running = undefined;
      });
    latest = await running;
    return latest;
  };
  await execute();
  const server = http.createServer(async (req, res) => {
    try {
      res.setHeader("cache-control", "no-store");
      res.setHeader("x-content-type-options", "nosniff");
      if (req.method === "GET" && req.url === "/health") {
        res.setHeader("content-type", "application/json; charset=utf-8");
        res.end(JSON.stringify({ ok: true, version: "0.2.0" }) + "\n");
        return;
      }
      if (req.method === "GET" && req.url === "/api/report") {
        res.setHeader("content-type", "application/json; charset=utf-8");
        res.end(JSON.stringify(latest, null, 2) + "\n");
        return;
      }
      if (req.method === "POST" && req.url === "/api/scan") {
        const result = await execute();
        res.setHeader("content-type", "application/json; charset=utf-8");
        res.end(JSON.stringify(result, null, 2) + "\n");
        return;
      }
      if (
        req.method === "GET" &&
        (req.url === "/" || req.url === "/index.html")
      ) {
        res.setHeader("content-type", "text/html; charset=utf-8");
        res.end(renderDashboard(latest!));
        return;
      }
      res.statusCode = 404;
      res.end("Not found\n");
    } catch {
      res.statusCode = 500;
      res.setHeader("content-type", "application/json; charset=utf-8");
      res.end(JSON.stringify({ error: "REAPER operation failed." }) + "\n");
    }
  });
  const port = options.port ?? 7337;
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => resolve());
  });
  const address = server.address();
  if (!address || typeof address === "string")
    throw new Error("Local service did not bind.");
  return { server, port: address.port };
}
