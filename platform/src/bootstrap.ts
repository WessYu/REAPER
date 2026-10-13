import { randomUUID } from "node:crypto";
import { Pool } from "pg";
import { createApiKeyMaterial } from "./auth.js";

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required.`);
  return value;
}

async function main(): Promise<void> {
  const pool = new Pool({
    connectionString: required("REAPER_PLATFORM_ADMIN_DATABASE_URL"),
    max: 1,
    application_name: "reaper-platform-bootstrap",
  });
  const pepper = required("REAPER_PLATFORM_API_KEY_PEPPER");
  const principalId = process.env.REAPER_PLATFORM_BOOTSTRAP_PRINCIPAL ?? "owner";
  const organizationName =
    process.env.REAPER_PLATFORM_BOOTSTRAP_ORGANIZATION ?? "REAPER";
  const workspaceName =
    process.env.REAPER_PLATFORM_BOOTSTRAP_WORKSPACE ?? "Default";
  const keyName = process.env.REAPER_PLATFORM_BOOTSTRAP_KEY_NAME ?? "bootstrap-admin";
  const organizationId = randomUUID();
  const workspaceId = randomUUID();
  const material = createApiKeyMaterial(pepper);

  try {
    await pool.query(
      `SELECT reaper_control.bootstrap_platform(
        $1::uuid,$2,$3::uuid,$4,$5,$6::uuid,$7,$8,$9::timestamptz
      )`,
      [
        organizationId,
        organizationName,
        workspaceId,
        workspaceName,
        principalId,
        material.id,
        keyName,
        material.secretHash,
        material.expiresAt,
      ],
    );
    console.log(
      JSON.stringify(
        {
          organizationId,
          workspaceId,
          principalId,
          apiKeyId: material.id,
          apiKey: material.token,
          warning: "Store this API key now; REAPER stores only its HMAC digest.",
        },
        null,
        2,
      ),
    );
  } finally {
    await pool.end();
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 2;
});
