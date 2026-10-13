import { Pool, type PoolClient, type PoolConfig } from "pg";
import type { RequestContext } from "./types.js";

const DEFAULT_STATEMENT_TIMEOUT_MS = 15_000;

export function createPlatformPool(connectionString: string): Pool {
  if (!connectionString) throw new Error("REAPER_PLATFORM_DATABASE_URL is required.");
  const config: PoolConfig = {
    connectionString,
    max: 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
    application_name: "reaper-platform",
  };
  return new Pool(config);
}

export async function withTransaction<T>(
  pool: Pool,
  work: (client: PoolClient) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      "SELECT set_config('statement_timeout', $1, true)",
      [String(DEFAULT_STATEMENT_TIMEOUT_MS)],
    );
    const result = await work(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch {
      // Preserve the original failure.
    }
    throw error;
  } finally {
    client.release();
  }
}

export async function withWorkspaceContext<T>(
  pool: Pool,
  context: RequestContext,
  work: (client: PoolClient) => Promise<T>,
): Promise<T> {
  return withTransaction(pool, async (client) => {
    await client.query(
      "SELECT set_config('reaper.workspace_id', $1, true), set_config('reaper.principal_id', $2, true)",
      [context.workspaceId, context.principalId],
    );
    return work(client);
  });
}
