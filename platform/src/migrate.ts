import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { Client } from "pg";

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required.`);
  return value;
}

async function main(): Promise<void> {
  const client = new Client({
    connectionString: required("REAPER_PLATFORM_ADMIN_DATABASE_URL"),
    application_name: "reaper-platform-migrate",
  });
  await client.connect();
  try {
    await client.query(
      "SELECT pg_advisory_lock(hashtext('reaper-platform-migrations'))",
    );
    for (const relative of [
      "../../control-plane/001_init.sql",
      "../../control-plane/002_platform.sql",
      "../../control-plane/003_staging_hardening.sql",
      "../../control-plane/004_cloud_run.sql",
      "../../control-plane/005_cloud_run_indexes.sql",
    ]) {
      const sql = await readFile(
        fileURLToPath(new URL(relative, import.meta.url)),
        "utf8",
      );
      await client.query(sql);
    }
  } finally {
    await client
      .query(
        "SELECT pg_advisory_unlock(hashtext('reaper-platform-migrations'))",
      )
      .catch(() => {});
    await client.end();
  }
}

main()
  .then(() => console.log("REAPER Platform migrations applied."))
  .catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 2;
  });
