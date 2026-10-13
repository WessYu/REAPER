import type {
  AuthorizationScopePayload,
  ScopeSigner,
  SignedAuthorizationScope,
} from "./scope-signer.js";
import { googleApiJson, type AccessTokenProvider } from "./gcp-auth.js";

function canonical(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean")
    return JSON.stringify(value);
  if (typeof value === "number" && Number.isFinite(value))
    return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (!value || typeof value !== "object")
    throw new Error("Scope contains a non-JSON value.");
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  return `{${keys
    .map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`)
    .join(",")}}`;
}

function crc32c(input: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of input) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++)
      crc = (crc >>> 1) ^ (crc & 1 ? 0x82f63b78 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function base64Url(input: Buffer): string {
  return input.toString("base64url");
}

function assertVersionName(value: string): void {
  if (
    !/^projects\/[a-z][a-z0-9-]{4,62}\/(?:locations)\/[a-z0-9-]+\/keyRings\/[A-Za-z0-9_-]{1,63}\/cryptoKeys\/[A-Za-z0-9_-]{1,63}\/cryptoKeyVersions\/[0-9]+$/.test(
      value,
    )
  )
    throw new Error("Cloud KMS key version resource name is invalid.");
}

export class GcpKmsScopeSigner implements ScopeSigner {
  readonly publicKeyPem: string;

  private constructor(
    private readonly keyVersionName: string,
    private readonly keyId: string,
    publicKeyPem: string,
    private readonly options: {
      fetchImpl?: typeof fetch;
      accessTokenProvider?: AccessTokenProvider;
    },
  ) {
    this.publicKeyPem = publicKeyPem;
  }

  static async create(
    input: {
      keyVersionName: string;
      keyId: string;
    },
    options: {
      fetchImpl?: typeof fetch;
      accessTokenProvider?: AccessTokenProvider;
    } = {},
  ): Promise<GcpKmsScopeSigner> {
    assertVersionName(input.keyVersionName);
    if (!/^[A-Za-z0-9._-]{1,100}$/.test(input.keyId))
      throw new Error("Cloud KMS scope key id is invalid.");
    const response = await googleApiJson<{
      pem?: unknown;
      algorithm?: unknown;
      name?: unknown;
    }>(
      `https://cloudkms.googleapis.com/v1/${input.keyVersionName}/publicKey`,
      { method: "GET" },
      options,
    );
    if (
      response.name !== input.keyVersionName ||
      response.algorithm !== "EC_SIGN_ED25519" ||
      typeof response.pem !== "string" ||
      !response.pem.includes("PUBLIC KEY")
    )
      throw new Error("Cloud KMS public key response is invalid.");
    return new GcpKmsScopeSigner(
      input.keyVersionName,
      input.keyId,
      response.pem,
      options,
    );
  }

  async sign(
    payload: AuthorizationScopePayload,
  ): Promise<SignedAuthorizationScope> {
    const data = Buffer.from(canonical(payload), "utf8");
    const requestCrc = crc32c(data);
    const response = await googleApiJson<{
      name?: unknown;
      signature?: unknown;
      signatureCrc32c?: unknown;
      verifiedDataCrc32c?: unknown;
    }>(
      `https://cloudkms.googleapis.com/v1/${this.keyVersionName}:asymmetricSign`,
      {
        method: "POST",
        body: JSON.stringify({
          data: data.toString("base64"),
          dataCrc32c: String(requestCrc),
        }),
      },
      this.options,
    );
    if (
      response.name !== this.keyVersionName ||
      response.verifiedDataCrc32c !== true ||
      typeof response.signature !== "string"
    )
      throw new Error(
        "Cloud KMS signing response failed integrity validation.",
      );
    const signature = Buffer.from(response.signature, "base64");
    const responseCrc = Number(response.signatureCrc32c);
    if (
      signature.byteLength !== 64 ||
      !Number.isSafeInteger(responseCrc) ||
      crc32c(signature) !== responseCrc
    )
      throw new Error("Cloud KMS signature checksum validation failed.");
    const encoded = base64Url(signature);
    if (!/^[A-Za-z0-9_-]{86}$/.test(encoded))
      throw new Error("Cloud KMS returned an invalid Ed25519 signature.");
    return {
      keyId: this.keyId,
      payload,
      signature: encoded,
    };
  }
}
