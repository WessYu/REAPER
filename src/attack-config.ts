import type {
  AttackConfig,
  AttackIdentity,
  AttackStep,
  VerifyJson,
} from "./model.js";

function strings(value: unknown): value is string[] {
  return (
    Array.isArray(value) &&
    value.every((item) => typeof item === "string" && item.length > 0)
  );
}

function positiveInteger(value: unknown, label: string, maximum: number): void {
  if (
    value !== undefined &&
    (!Number.isSafeInteger(value) ||
      Number(value) < 1 ||
      Number(value) > maximum)
  )
    throw new Error(`${label} must be an integer between 1 and ${maximum}.`);
}

function jsonLiteral(input: unknown): input is VerifyJson {
  if (
    input === null ||
    typeof input === "string" ||
    typeof input === "number" ||
    typeof input === "boolean"
  )
    return true;
  if (Array.isArray(input)) return input.every(jsonLiteral);
  if (typeof input === "object")
    return Object.values(input as Record<string, unknown>).every(jsonLiteral);
  return false;
}

function envName(value: unknown): boolean {
  return typeof value === "string" && /^[A-Z_][A-Z0-9_]*$/i.test(value);
}

function validateStep(
  value: unknown,
  label: string,
  identities: Set<string>,
): AttackStep {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error(`${label} must be an object.`);
  const step = value as Record<string, unknown>;
  const allowed = new Set([
    "name",
    "path",
    "method",
    "identity",
    "headers",
    "body",
    "multipart",
    "expectStatus",
    "capture",
  ]);
  for (const key of Object.keys(step))
    if (!allowed.has(key)) throw new Error(`Unknown ${label} key: ${key}`);
  if (typeof step.name !== "string" || !step.name.trim())
    throw new Error(`${label}.name must be non-empty.`);
  if (
    typeof step.path !== "string" ||
    !step.path.startsWith("/") ||
    step.path.startsWith("//")
  )
    throw new Error(`${label}.path must be an origin-relative path.`);
  if (
    step.method !== undefined &&
    !["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"].includes(
      String(step.method),
    )
  )
    throw new Error(`${label}.method is invalid.`);
  if (
    step.identity !== undefined &&
    (typeof step.identity !== "string" || !identities.has(step.identity))
  )
    throw new Error(`${label}.identity must reference a configured identity.`);
  if (step.headers !== undefined) {
    if (
      !step.headers ||
      typeof step.headers !== "object" ||
      Array.isArray(step.headers)
    )
      throw new Error(`${label}.headers must be an object.`);
    const blocked = new Set([
      "authorization",
      "cookie",
      "host",
      "content-length",
      "proxy-authorization",
      "x-reaper-trace-id",
    ]);
    for (const [name, headerValue] of Object.entries(
      step.headers as Record<string, unknown>,
    )) {
      if (!/^[A-Za-z0-9-]+$/.test(name) || blocked.has(name.toLowerCase()))
        throw new Error(`${label}.headers contains a blocked header: ${name}`);
      if (typeof headerValue !== "string")
        throw new Error(`${label}.headers values must be strings.`);
    }
  }
  if (step.body !== undefined && !jsonLiteral(step.body))
    throw new Error(`${label}.body must be literal JSON.`);
  if (step.body !== undefined && step.multipart !== undefined)
    throw new Error(`${label} cannot set both body and multipart.`);
  if (step.multipart !== undefined) {
    if (
      !step.multipart ||
      typeof step.multipart !== "object" ||
      Array.isArray(step.multipart)
    )
      throw new Error(`${label}.multipart must be an object.`);
    const multipart = step.multipart as Record<string, unknown>;
    for (const key of Object.keys(multipart))
      if (!["fields", "files"].includes(key))
        throw new Error(`Unknown ${label}.multipart key: ${key}`);
    if (multipart.fields !== undefined) {
      if (
        !multipart.fields ||
        typeof multipart.fields !== "object" ||
        Array.isArray(multipart.fields) ||
        !Object.entries(multipart.fields as Record<string, unknown>).every(
          ([name, fieldValue]) =>
            /^[A-Za-z0-9_.-]{1,80}$/.test(name) &&
            typeof fieldValue === "string",
        )
      )
        throw new Error(
          `${label}.multipart.fields must map safe field names to strings.`,
        );
    }
    if (multipart.files !== undefined) {
      if (!Array.isArray(multipart.files) || multipart.files.length > 8)
        throw new Error(`${label}.multipart.files cannot exceed 8 files.`);
      for (const [index, file] of multipart.files.entries()) {
        if (!file || typeof file !== "object" || Array.isArray(file))
          throw new Error(
            `${label}.multipart.files[${index}] must be an object.`,
          );
        const item = file as Record<string, unknown>;
        for (const key of Object.keys(item))
          if (!["field", "filename", "content", "contentType"].includes(key))
            throw new Error(
              `Unknown ${label}.multipart.files[${index}] key: ${key}`,
            );
        if (
          typeof item.field !== "string" ||
          !/^[A-Za-z0-9_.-]{1,80}$/.test(item.field)
        )
          throw new Error(
            `${label}.multipart.files[${index}].field is invalid.`,
          );
        if (
          typeof item.filename !== "string" ||
          item.filename.length < 1 ||
          item.filename.length > 160 ||
          /[\\/\0]/.test(item.filename)
        )
          throw new Error(
            `${label}.multipart.files[${index}].filename is invalid.`,
          );
        if (typeof item.content !== "string")
          throw new Error(
            `${label}.multipart.files[${index}].content must be a string.`,
          );
        if (
          item.contentType !== undefined &&
          (typeof item.contentType !== "string" ||
            !/^[A-Za-z0-9.+-]+\/[A-Za-z0-9.+-]+$/.test(item.contentType))
        )
          throw new Error(
            `${label}.multipart.files[${index}].contentType is invalid.`,
          );
      }
    }
  }
  if (
    step.expectStatus !== undefined &&
    (!Number.isSafeInteger(step.expectStatus) ||
      Number(step.expectStatus) < 100 ||
      Number(step.expectStatus) > 599)
  )
    throw new Error(`${label}.expectStatus must be an HTTP status.`);
  if (step.capture !== undefined) {
    if (
      !step.capture ||
      typeof step.capture !== "object" ||
      Array.isArray(step.capture) ||
      !Object.entries(step.capture as Record<string, unknown>).every(
        ([name, path]) =>
          /^[A-Z_][A-Z0-9_]*$/i.test(name) &&
          typeof path === "string" &&
          path.length > 0,
      )
    )
      throw new Error(
        `${label}.capture must map variable names to JSON paths.`,
      );
  }
  return step as unknown as AttackStep;
}

function validateIdentity(value: unknown, label: string): AttackIdentity {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error(`${label} must be an object.`);
  const identity = value as Record<string, unknown>;
  const allowed = new Set([
    "authEnv",
    "authVar",
    "cookieEnv",
    "cookieVar",
    "role",
    "privilegeLevel",
    "tenant",
  ]);
  for (const key of Object.keys(identity))
    if (!allowed.has(key)) throw new Error(`Unknown ${label} key: ${key}`);
  if (identity.authEnv !== undefined && !envName(identity.authEnv))
    throw new Error(`${label}.authEnv must be an environment variable name.`);
  if (identity.authVar !== undefined && !envName(identity.authVar))
    throw new Error(`${label}.authVar must be a captured variable name.`);
  if (identity.authEnv !== undefined && identity.authVar !== undefined)
    throw new Error(`${label} cannot set both authEnv and authVar.`);
  if (identity.cookieEnv !== undefined && !envName(identity.cookieEnv))
    throw new Error(`${label}.cookieEnv must be an environment variable name.`);
  if (identity.cookieVar !== undefined && !envName(identity.cookieVar))
    throw new Error(`${label}.cookieVar must be a captured variable name.`);
  if (identity.cookieEnv !== undefined && identity.cookieVar !== undefined)
    throw new Error(`${label} cannot set both cookieEnv and cookieVar.`);
  for (const key of ["role", "tenant"])
    if (
      identity[key] !== undefined &&
      (typeof identity[key] !== "string" || !String(identity[key]).trim())
    )
      throw new Error(`${label}.${key} must be a non-empty string.`);
  if (
    identity.privilegeLevel !== undefined &&
    (!Number.isSafeInteger(identity.privilegeLevel) ||
      Number(identity.privilegeLevel) < 0 ||
      Number(identity.privilegeLevel) > 100)
  )
    throw new Error(`${label}.privilegeLevel must be between 0 and 100.`);
  return identity as unknown as AttackIdentity;
}

export function validateAttackConfig(value: unknown): AttackConfig {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("attack must be an object.");
  const config = value as Record<string, unknown>;
  const allowed = new Set([
    "scope",
    "maxRequests",
    "maxMutationRequests",
    "maxUploadBytes",
    "timeoutMs",
    "rateLimitPerSecond",
    "maxServerErrors",
    "allowMutations",
    "identities",
    "scenarios",
  ]);
  for (const key of Object.keys(config))
    if (!allowed.has(key)) throw new Error(`Unknown attack key: ${key}`);

  if (
    !config.scope ||
    typeof config.scope !== "object" ||
    Array.isArray(config.scope)
  )
    throw new Error("attack.scope must be an object.");
  const scope = config.scope as Record<string, unknown>;
  const scopeAllowed = new Set([
    "authorized",
    "authorizationId",
    "expiresAt",
    "environment",
    "allowedTargets",
    "pathPrefixes",
    "allowProduction",
    "allowProductionMutations",
  ]);
  for (const key of Object.keys(scope))
    if (!scopeAllowed.has(key))
      throw new Error(`Unknown attack.scope key: ${key}`);
  if (scope.authorized !== true)
    throw new Error("attack.scope.authorized must be explicitly true.");
  if (
    scope.authorizationId !== undefined &&
    (typeof scope.authorizationId !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/.test(scope.authorizationId))
  )
    throw new Error("attack.scope.authorizationId is invalid.");
  if (scope.expiresAt !== undefined) {
    if (
      typeof scope.expiresAt !== "string" ||
      !Number.isFinite(Date.parse(scope.expiresAt))
    )
      throw new Error("attack.scope.expiresAt must be an ISO date-time.");
  }
  if (
    !["local", "preview", "staging", "production"].includes(
      String(scope.environment),
    )
  )
    throw new Error("attack.scope.environment is invalid.");
  if (scope.allowedTargets !== undefined && !strings(scope.allowedTargets))
    throw new Error("attack.scope.allowedTargets must be a string array.");
  if (scope.pathPrefixes !== undefined && !strings(scope.pathPrefixes))
    throw new Error("attack.scope.pathPrefixes must be a string array.");
  if (
    scope.allowProduction !== undefined &&
    typeof scope.allowProduction !== "boolean"
  )
    throw new Error("attack.scope.allowProduction must be boolean.");
  if (
    scope.allowProductionMutations !== undefined &&
    typeof scope.allowProductionMutations !== "boolean"
  )
    throw new Error("attack.scope.allowProductionMutations must be boolean.");
  if (scope.environment === "production") {
    if (scope.allowProduction !== true)
      throw new Error(
        "Production attack scenarios require attack.scope.allowProduction=true.",
      );
    if (
      typeof scope.authorizationId !== "string" ||
      !scope.authorizationId.trim()
    )
      throw new Error(
        "Production attack scenarios require attack.scope.authorizationId.",
      );
    if (typeof scope.expiresAt !== "string")
      throw new Error(
        "Production attack scenarios require attack.scope.expiresAt.",
      );
  }

  positiveInteger(config.maxRequests, "attack.maxRequests", 500);
  positiveInteger(config.maxMutationRequests, "attack.maxMutationRequests", 50);
  positiveInteger(config.maxUploadBytes, "attack.maxUploadBytes", 1048576);
  positiveInteger(config.timeoutMs, "attack.timeoutMs", 30000);
  positiveInteger(config.rateLimitPerSecond, "attack.rateLimitPerSecond", 20);
  positiveInteger(config.maxServerErrors, "attack.maxServerErrors", 20);
  if (
    config.allowMutations !== undefined &&
    typeof config.allowMutations !== "boolean"
  )
    throw new Error("attack.allowMutations must be boolean.");
  if (
    scope.environment === "production" &&
    config.allowMutations === true &&
    scope.allowProductionMutations !== true
  )
    throw new Error(
      "Production mutations require attack.scope.allowProductionMutations=true.",
    );
  if (
    scope.environment === "production" &&
    config.maxMutationRequests !== undefined &&
    Number(config.maxMutationRequests) > 5
  )
    throw new Error("Production attack.maxMutationRequests cannot exceed 5.");
  if (
    scope.environment === "production" &&
    config.rateLimitPerSecond !== undefined &&
    Number(config.rateLimitPerSecond) > 5
  )
    throw new Error("Production attack.rateLimitPerSecond cannot exceed 5.");

  if (
    !config.identities ||
    typeof config.identities !== "object" ||
    Array.isArray(config.identities)
  )
    throw new Error("attack.identities must be an object.");
  const identities = new Set(Object.keys(config.identities));
  if (!identities.size) throw new Error("attack.identities cannot be empty.");
  for (const [name, identity] of Object.entries(
    config.identities as Record<string, unknown>,
  )) {
    if (!/^[A-Za-z][A-Za-z0-9_-]*$/.test(name))
      throw new Error(`Invalid attack identity name: ${name}`);
    validateIdentity(identity, `attack.identities.${name}`);
  }

  if (!Array.isArray(config.scenarios) || config.scenarios.length < 1)
    throw new Error("attack.scenarios must be a non-empty array.");
  if (config.scenarios.length > 100)
    throw new Error("attack.scenarios cannot exceed 100 entries.");

  for (let index = 0; index < config.scenarios.length; index++) {
    const raw = config.scenarios[index];
    const label = `attack.scenarios[${index}]`;
    if (!raw || typeof raw !== "object" || Array.isArray(raw))
      throw new Error(`${label} must be an object.`);
    const scenario = raw as Record<string, unknown>;
    const scenarioAllowed = new Set([
      "name",
      "kind",
      "attackerIdentity",
      "ownerIdentity",
      "setup",
      "attack",
      "cleanup",
      "denyStatuses",
      "expect",
      "resource",
      "sourceFindingId",
    ]);
    for (const key of Object.keys(scenario))
      if (!scenarioAllowed.has(key))
        throw new Error(`Unknown ${label} key: ${key}`);
    if (typeof scenario.name !== "string" || !scenario.name.trim())
      throw new Error(`${label}.name must be non-empty.`);
    if (
      !["bola", "tenant", "privilege", "authorization"].includes(
        String(scenario.kind),
      )
    )
      throw new Error(`${label}.kind is invalid.`);
    if (
      typeof scenario.attackerIdentity !== "string" ||
      !identities.has(scenario.attackerIdentity)
    )
      throw new Error(
        `${label}.attackerIdentity must reference a configured identity.`,
      );
    if (
      scenario.ownerIdentity !== undefined &&
      (typeof scenario.ownerIdentity !== "string" ||
        !identities.has(scenario.ownerIdentity))
    )
      throw new Error(
        `${label}.ownerIdentity must reference a configured identity.`,
      );
    if (
      ["bola", "tenant"].includes(String(scenario.kind)) &&
      scenario.ownerIdentity === undefined
    )
      throw new Error(`${label}.ownerIdentity is required for this kind.`);
    if (
      scenario.ownerIdentity !== undefined &&
      scenario.ownerIdentity === scenario.attackerIdentity
    )
      throw new Error(
        `${label} attackerIdentity and ownerIdentity must differ.`,
      );
    for (const phase of ["setup", "cleanup"]) {
      const steps = scenario[phase];
      if (steps === undefined) continue;
      if (!Array.isArray(steps))
        throw new Error(`${label}.${phase} must be an array.`);
      if (steps.length > 20)
        throw new Error(`${label}.${phase} cannot exceed 20 steps.`);
      steps.forEach((step, stepIndex) =>
        validateStep(step, `${label}.${phase}[${stepIndex}]`, identities),
      );
    }
    validateStep(scenario.attack, `${label}.attack`, identities);
    if (
      (scenario.attack as Record<string, unknown>).identity !== undefined &&
      (scenario.attack as Record<string, unknown>).identity !==
        scenario.attackerIdentity
    )
      throw new Error(
        `${label}.attack.identity must match attackerIdentity when provided.`,
      );
    if (scenario.denyStatuses !== undefined) {
      if (
        !Array.isArray(scenario.denyStatuses) ||
        !scenario.denyStatuses.length ||
        !scenario.denyStatuses.every(
          (status) =>
            Number.isSafeInteger(status) &&
            Number(status) >= 100 &&
            Number(status) <= 599,
        )
      )
        throw new Error(`${label}.denyStatuses must contain HTTP statuses.`);
    }
    if (scenario.expect !== undefined) {
      if (
        !scenario.expect ||
        typeof scenario.expect !== "object" ||
        Array.isArray(scenario.expect)
      )
        throw new Error(`${label}.expect must be an object.`);
      const expectation = scenario.expect as Record<string, unknown>;
      for (const key of Object.keys(expectation))
        if (
          ![
            "statuses",
            "headers",
            "absentHeaders",
            "json",
            "absentJsonPaths",
          ].includes(key)
        )
          throw new Error(`Unknown ${label}.expect key: ${key}`);
      if (
        expectation.statuses !== undefined &&
        (!Array.isArray(expectation.statuses) ||
          !expectation.statuses.length ||
          !expectation.statuses.every(
            (status) =>
              Number.isSafeInteger(status) &&
              Number(status) >= 100 &&
              Number(status) <= 599,
          ))
      )
        throw new Error(`${label}.expect.statuses must contain HTTP statuses.`);
      const sensitive = new Set([
        "authorization",
        "cookie",
        "set-cookie",
        "proxy-authorization",
      ]);
      if (expectation.headers !== undefined) {
        if (
          !expectation.headers ||
          typeof expectation.headers !== "object" ||
          Array.isArray(expectation.headers)
        )
          throw new Error(`${label}.expect.headers must be an object.`);
        for (const [name, expectedValue] of Object.entries(
          expectation.headers as Record<string, unknown>,
        )) {
          if (
            !/^[A-Za-z0-9-]+$/.test(name) ||
            sensitive.has(name.toLowerCase()) ||
            typeof expectedValue !== "string"
          )
            throw new Error(
              `${label}.expect.headers contains an invalid header.`,
            );
        }
      }
      if (
        expectation.absentHeaders !== undefined &&
        (!strings(expectation.absentHeaders) ||
          expectation.absentHeaders.some(
            (name) =>
              !/^[A-Za-z0-9-]+$/.test(name) ||
              sensitive.has(name.toLowerCase()),
          ))
      )
        throw new Error(
          `${label}.expect.absentHeaders must contain non-sensitive header names.`,
        );
      if (expectation.json !== undefined) {
        if (
          !expectation.json ||
          typeof expectation.json !== "object" ||
          Array.isArray(expectation.json)
        )
          throw new Error(`${label}.expect.json must be an object.`);
        for (const [path, expectedValue] of Object.entries(
          expectation.json as Record<string, unknown>,
        ))
          if (
            !/^[A-Za-z0-9_.-]+$/.test(path) ||
            !(
              expectedValue === null ||
              typeof expectedValue === "string" ||
              typeof expectedValue === "number" ||
              typeof expectedValue === "boolean"
            )
          )
            throw new Error(
              `${label}.expect.json must map JSON paths to primitive values.`,
            );
      }
      if (
        expectation.absentJsonPaths !== undefined &&
        (!strings(expectation.absentJsonPaths) ||
          expectation.absentJsonPaths.some(
            (path) => !/^[A-Za-z0-9_.-]+$/.test(path),
          ))
      )
        throw new Error(
          `${label}.expect.absentJsonPaths must contain JSON paths.`,
        );
    }
    if (
      ["session", "cors", "csrf", "business"].includes(String(scenario.kind)) &&
      scenario.expect === undefined &&
      (scenario.attack as Record<string, unknown>).expectStatus === undefined
    )
      throw new Error(
        `${label} requires expect or attack.expectStatus for this scenario kind.`,
      );
    for (const key of ["resource", "sourceFindingId"])
      if (
        scenario[key] !== undefined &&
        (typeof scenario[key] !== "string" || !String(scenario[key]).trim())
      )
        throw new Error(`${label}.${key} must be a non-empty string.`);

    const mutating = [
      ...(Array.isArray(scenario.setup) ? scenario.setup : []),
      scenario.attack,
      ...(Array.isArray(scenario.cleanup) ? scenario.cleanup : []),
    ].some((step) =>
      ["POST", "PUT", "PATCH", "DELETE"].includes(
        String((step as Record<string, unknown>).method ?? "GET"),
      ),
    );
    if (mutating && config.allowMutations !== true)
      throw new Error(
        `${label} contains mutating requests but attack.allowMutations is not true.`,
      );
  }

  return config as unknown as AttackConfig;
}
