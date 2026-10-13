export interface SecretRequestContext {
  runId: string;
  targetOrigin: string;
  purpose: string;
}

export interface SecretProvider {
  get(
    reference: string,
    context: SecretRequestContext,
  ): string | undefined | Promise<string | undefined>;
  revoke?(
    reference: string,
    context: SecretRequestContext,
  ): void | Promise<void>;
}

export class EnvironmentSecretProvider implements SecretProvider {
  get(reference: string): string | undefined {
    if (!/^[A-Z_][A-Z0-9_]*$/i.test(reference)) return undefined;
    return process.env[reference];
  }

  revoke(): void {}
}

export class InMemorySecretProvider implements SecretProvider {
  readonly #secrets: Map<string, string>;

  constructor(secrets: Record<string, string>) {
    this.#secrets = new Map(Object.entries(secrets));
  }

  get(reference: string): string | undefined {
    return this.#secrets.get(reference);
  }

  revoke(reference: string): void {
    this.#secrets.delete(reference);
  }
}
