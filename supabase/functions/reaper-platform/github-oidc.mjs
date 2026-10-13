const ISSUER = "https://token.actions.githubusercontent.com";
const DISCOVERY_URL =
  "https://token.actions.githubusercontent.com/.well-known/openid-configuration";
const AUDIENCE = "reaper-staging";
const REPOSITORY = "WessYu/REAPER";
const WORKFLOW_REF =
  "WessYu/REAPER/.github/workflows/free-runner.yml@refs/heads/main";

let cachedJwks;
let cachedUntil = 0;

function decodeBase64Url(value) {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function decodeJsonPart(value) {
  const bytes = decodeBase64Url(value);
  return JSON.parse(new TextDecoder().decode(bytes));
}

function audienceMatches(value) {
  if (typeof value === "string") return value === AUDIENCE;
  return Array.isArray(value) && value.includes(AUDIENCE);
}

async function fetchJson(url, fetchImpl) {
  if (!url.startsWith("https://"))
    throw new Error("OIDC metadata must use HTTPS.");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5_000);
  try {
    const response = await fetchImpl(url, {
      redirect: "error",
      signal: controller.signal,
      headers: { accept: "application/json" },
    });
    if (!response.ok)
      throw new Error(
        `OIDC metadata request failed with HTTP ${response.status}.`,
      );
    return await response.json();
  } finally {
    clearTimeout(timeout);
  }
}

async function loadJwks(fetchImpl, force = false) {
  if (!force && cachedJwks && Date.now() < cachedUntil) return cachedJwks;
  const discovery = await fetchJson(DISCOVERY_URL, fetchImpl);
  if (
    discovery.issuer !== ISSUER ||
    typeof discovery.jwks_uri !== "string" ||
    !discovery.jwks_uri.startsWith(ISSUER + "/")
  )
    throw new Error("GitHub OIDC discovery metadata is invalid.");
  const jwks = await fetchJson(discovery.jwks_uri, fetchImpl);
  if (!jwks || !Array.isArray(jwks.keys))
    throw new Error("GitHub OIDC JWKS response is invalid.");
  cachedJwks = jwks;
  cachedUntil = Date.now() + 5 * 60_000;
  return jwks;
}

async function findKey(kid, fetchImpl) {
  let jwks = await loadJwks(fetchImpl);
  let key = jwks.keys.find(
    (candidate) =>
      candidate &&
      candidate.kid === kid &&
      candidate.kty === "RSA" &&
      (!candidate.use || candidate.use === "sig") &&
      (!candidate.alg || candidate.alg === "RS256"),
  );
  if (!key) {
    jwks = await loadJwks(fetchImpl, true);
    key = jwks.keys.find(
      (candidate) =>
        candidate &&
        candidate.kid === kid &&
        candidate.kty === "RSA" &&
        (!candidate.use || candidate.use === "sig") &&
        (!candidate.alg || candidate.alg === "RS256"),
    );
  }
  if (!key) throw new Error("GitHub OIDC signing key is unknown.");
  return key;
}

export async function verifyGitHubRunnerToken(
  token,
  { fetchImpl = fetch, now = Date.now() } = {},
) {
  if (typeof token !== "string" || token.length < 100 || token.length > 20_000)
    throw new Error("GitHub OIDC token is invalid.");
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("GitHub OIDC token is malformed.");

  const header = decodeJsonPart(parts[0]);
  const claims = decodeJsonPart(parts[1]);
  if (
    !header ||
    header.alg !== "RS256" ||
    typeof header.kid !== "string" ||
    header.kid.length < 1 ||
    header.kid.length > 200
  )
    throw new Error("GitHub OIDC header is invalid.");

  const jwk = await findKey(header.kid, fetchImpl);
  const key = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const verified = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    decodeBase64Url(parts[2]),
    new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
  );
  if (!verified) throw new Error("GitHub OIDC signature is invalid.");

  const nowSeconds = Math.floor(now / 1000);
  if (
    claims.iss !== ISSUER ||
    !audienceMatches(claims.aud) ||
    typeof claims.exp !== "number" ||
    claims.exp < nowSeconds - 30 ||
    typeof claims.iat !== "number" ||
    claims.iat > nowSeconds + 60 ||
    claims.exp - claims.iat > 20 * 60 ||
    (typeof claims.nbf === "number" && claims.nbf > nowSeconds + 30)
  )
    throw new Error("GitHub OIDC timing or audience claims are invalid.");

  if (
    claims.repository !== REPOSITORY ||
    claims.ref !== "refs/heads/main" ||
    claims.workflow_ref !== WORKFLOW_REF ||
    !["schedule", "workflow_dispatch"].includes(claims.event_name) ||
    !/^[0-9]{1,30}$/.test(String(claims.run_id ?? "")) ||
    !/^[0-9]{1,10}$/.test(String(claims.run_attempt ?? ""))
  )
    throw new Error("GitHub OIDC repository or workflow claims are invalid.");

  return {
    repository: claims.repository,
    workflowRef: claims.workflow_ref,
    eventName: claims.event_name,
    runId: String(claims.run_id),
    runAttempt: String(claims.run_attempt),
    actor: typeof claims.actor === "string" ? claims.actor : "unknown",
    workerId: `gha:${claims.run_id}:${claims.run_attempt}`,
  };
}

export function parseRunnerBearer(request) {
  const header = request.headers.get("authorization");
  const match = header ? /^Bearer ([^\s]+)$/.exec(header) : null;
  if (!match?.[1]) throw new Error("Runner authentication failed.");
  return match[1];
}
