import test from "node:test";
import assert from "node:assert/strict";
import {
  generateKeyPairSync,
  createSign,
} from "node:crypto";
import {
  verifyGitHubRunnerToken,
} from "../../supabase/functions/reaper-platform/github-oidc.mjs";

function encode(value) {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function token(privateKey, payload) {
  const header = encode({ alg: "RS256", typ: "JWT", kid: "test-key" });
  const body = encode(payload);
  const signer = createSign("RSA-SHA256");
  signer.update(header + "." + body);
  signer.end();
  const signature = signer.sign(privateKey).toString("base64url");
  return header + "." + body + "." + signature;
}

test("GitHub OIDC verifier accepts only the REAPER main free-runner workflow", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const jwk = publicKey.export({ format: "jwk" });
  jwk.kid = "test-key";
  jwk.alg = "RS256";
  jwk.use = "sig";

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: "https://token.actions.githubusercontent.com",
    aud: "reaper-staging",
    iat: now - 5,
    nbf: now - 5,
    exp: now + 300,
    repository: "WessYu/REAPER",
    ref: "refs/heads/main",
    workflow_ref:
      "WessYu/REAPER/.github/workflows/free-runner.yml@refs/heads/main",
    event_name: "workflow_dispatch",
    run_id: "123456789",
    run_attempt: "2",
    actor: "WessYu",
  };

  const fetchImpl = async (url) => {
    if (
      String(url) ===
      "https://token.actions.githubusercontent.com/.well-known/openid-configuration"
    ) {
      return Response.json({
        issuer: "https://token.actions.githubusercontent.com",
        jwks_uri:
          "https://token.actions.githubusercontent.com/.well-known/jwks",
      });
    }
    if (
      String(url) ===
      "https://token.actions.githubusercontent.com/.well-known/jwks"
    ) {
      return Response.json({ keys: [jwk] });
    }
    throw new Error("unexpected URL: " + String(url));
  };

  const identity = await verifyGitHubRunnerToken(token(privateKey, payload), {
    fetchImpl,
  });
  assert.equal(identity.workerId, "gha:123456789:2");
  assert.equal(identity.repository, "WessYu/REAPER");

  await assert.rejects(
    () =>
      verifyGitHubRunnerToken(
        token(privateKey, {
          ...payload,
          workflow_ref:
            "WessYu/REAPER/.github/workflows/ci.yml@refs/heads/main",
        }),
        { fetchImpl },
      ),
    /workflow claims are invalid/,
  );

  await assert.rejects(
    () =>
      verifyGitHubRunnerToken(
        token(privateKey, {
          ...payload,
          ref: "refs/heads/feature",
        }),
        { fetchImpl },
      ),
    /workflow claims are invalid/,
  );
});
