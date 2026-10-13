export type AccessTokenProvider = () => Promise<string>;

const METADATA_TOKEN_URL =
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";

export async function googleMetadataAccessToken(
  fetchImpl: typeof fetch = fetch,
): Promise<string> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 3_000);
  try {
    const response = await fetchImpl(METADATA_TOKEN_URL, {
      headers: { "Metadata-Flavor": "Google" },
      redirect: "error",
      signal: controller.signal,
    });
    if (!response.ok)
      throw new Error(`Google metadata token endpoint returned HTTP ${response.status}.`);
    const value = (await response.json()) as {
      access_token?: unknown;
      token_type?: unknown;
      expires_in?: unknown;
    };
    if (
      typeof value.access_token !== "string" ||
      value.access_token.length < 20 ||
      value.token_type !== "Bearer" ||
      !Number.isFinite(Number(value.expires_in)) ||
      Number(value.expires_in) < 60
    )
      throw new Error("Google metadata token response is invalid.");
    return value.access_token;
  } finally {
    clearTimeout(timeout);
  }
}

export async function googleApiJson<T>(
  url: string,
  init: RequestInit,
  options: {
    fetchImpl?: typeof fetch;
    accessTokenProvider?: AccessTokenProvider;
    timeoutMs?: number;
  } = {},
): Promise<T> {
  if (!url.startsWith("https://"))
    throw new Error("Google API requests must use HTTPS.");
  const fetchImpl = options.fetchImpl ?? fetch;
  const tokenProvider =
    options.accessTokenProvider ?? (() => googleMetadataAccessToken(fetchImpl));
  const token = await tokenProvider();
  const controller = new AbortController();
  const timeout = setTimeout(
    () => controller.abort(),
    options.timeoutMs ?? 10_000,
  );
  try {
    const response = await fetchImpl(url, {
      ...init,
      redirect: "error",
      signal: controller.signal,
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
        ...(init.headers ?? {}),
      },
    });
    const body = await response.text();
    if (!response.ok)
      throw new Error(
        `Google API request failed with HTTP ${response.status}: ${body.slice(0, 1000)}`,
      );
    return (body ? JSON.parse(body) : {}) as T;
  } finally {
    clearTimeout(timeout);
  }
}
