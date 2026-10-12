import type {
  AttackConfig,
  AttackStep,
  VerifyJson,
} from "./model.js";

const envName = /^[A-Z_][A-Z0-9_]*$/i;
const scenarioId = /^[a-z0-9][a-z0-9._-]{1,63}$/i;

function strings(value: unknown): value is string[] {
  return (
    Array.isArray(value) &&
    value.length > 0 &&
    value.every((item) => typeof item === "string" && item.length > 0)
  );
}

function jsonLiteral(value: unknown): value is VerifyJson {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  )
    return true;
  if (Array.isArray(value)) return value.every(jsonLiteral);
  if (typeof value === "object")
    return Object.values(value as Record<string, unknown>).every(jsonLiteral);
  return false;
}

function statusList(value: unknown, label: string): number[] | undefined {
  if (value === undefined) return undefined;
  if (
    !Array.isArray(value) ||
    value.length < 1 ||
    !value.every(
      (status) =>
        Number.isSafeInteger(status) && Number(status) >= 100 && Number(status) <= 599,
    )
  )
    throw new Error(`${label} must be a non-empty HTTP status array.`);
  return value as number[];
}

function validateStep(
  value: unknown,
  label: string,
  identities: Set<string>,
  allowMutations: boolean,
): AttackStep {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error(`${label} must be an object.`);
  const item = value as Record<string, unknown>;
  const allowed = new Set([
    "name",
    "path",
    "method",
    "actor",
    "body",
    "expect",
    "capture",
    "resource",
  ]);
  for (const key of Object.keys(item))
    if (!allowed.has(key)) throw new Error(`Unknown ${label} key: ${key}`);
  if (typeof item.name !== "string" || item.name.trim().length < 1)
    throw new Error(`${label}.name must be non-empty.`);
  if (
    typeof item.path !== "string" ||
    !item.path.startsWith("/") ||
    item.path.startsWith("//")
  )
    throw new Error(`${label}.path must be origin-relative.`);
  const method = String(item.method ?? "GET").toUpperCase();
  if (!["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"].includes(method))
    throw new Error(`${label}.method is unsupported.`);
  if (!["GET", "HEAD"].includes(method) && !allowMutations)
    throw new Error(
      `${label} uses ${method}; attack.allowMutations must be true.`,
    );
  if (item.actor !== undefined) {
    if (typeof item.actor !== "string" || !identities.has(item.actor))
      throw new Error(`${label}.actor must reference a configured identity.`);
  }
  if (item.body !== undefined && !jsonLiteral(item.body))
    throw new Error(`${label}.body must be literal JSON.`);
  if (item.resource !== undefined && typeof item.resource !== "string")
    throw new Error(`${label}.resource must be a string.`);
  if (item.capture !== undefined) {
    if (
      !item.capture ||
      typeof item.capture !== "object" ||
      Array.isArray(item.capture) ||
      !Object.entries(item.capture as Record<string, unknown>).every(
        ([name, path]) =>
          envName.test(name) && typeof path === "string" && path.length > 0,
      )
    )
      throw new Error(
        `${label}.capture must map variable names to JSON paths.`,
      );
  }
  if (item.expect !== undefined) {
    if (
      !item.expect ||
      typeof item.expect !== "object" ||
      Array.isArray(item.expect)
    )
      throw new Error(`${label}.expect must be an object.`);
    const expect = item.expect as Record<string, unknown>;
    for (const key of Object.keys(expect))
      if (!["deniedStatuses", "allowedStatuses"].includes(key))
        throw new Error(`Unknown ${label}.expect key: ${key}`);
    const denied = statusList(expect.deniedStatuses, `${label}.expect.deniedStatuses`);
    const allowedStatuses = statusList(
      expect.allowedStatuses,
      `${label}.expect.allowedStatuses`,
    );
    if (denied && allowedStatuses)
      throw new Error(
        `${label}.expect cannot define both deniedStatuses and allowedStatuses.`,
      );
    if (!denied && !allowedStatuses)
      throw new Error(`${label}.expect requires a status policy.`);
  }
  return item as unknown as AttackStep;
}

export function validateAttackConfig(value: unknown): AttackConfig {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("attack must be an object.");
  const attack = value as Record<string, unknown>;
  const allowed = new Set([
    "allowedTargets",
    "authorization",
    "maxRequests",
    "timeoutMs",
    "rateLimitPerSecond",
    "maxConsecutiveServerErrors",
    "allowMutations",
    "identities",
    "scenarios",
  ]);
  for (const key of Object.keys(attack))
    if (!allowed.has(key)) throw new Error(`Unknown attack key: ${key}`);

  if (!strings(attack.allowedTargets))
    throw new Error("attack.allowedTargets must be a non-empty string array.");
  for (const target of attack.allowedTargets)
    try {
      const url = new URL(target);
      if (
        !["http:", "https:"].includes(url.protocol) ||
        url.pathname !== "/" ||
        url.search !== "" ||
        url.hash !== "" ||
        url.username !== "" ||
        url.password !== ""
      )
        throw new Error();
    } catch {
      throw new Error(
        "attack.allowedTargets entries must be HTTP(S) origins without paths.",
      );
    }

  if (
    !attack.authorization ||
    typeof attack.authorization !== "object" ||
    Array.isArray(attack.authorization)
  )
    throw new Error("attack.authorization is required.");
  const authorization = attack.authorization as Record<string, unknown>;
  for (const key of Object.keys(authorization))
    if (!["acknowledged", "reference", "environment"].includes(key))
      throw new Error(`Unknown attack.authorization key: ${key}`);
  if (authorization.acknowledged !== true)
    throw new Error("attack.authorization.acknowledged must be true.");
  if (
    typeof authorization.reference !== "string" ||
    authorization.reference.trim().length < 3
  )
    throw new Error("attack.authorization.reference is required.");
  if (
    !["local", "preview", "staging", "production"].includes(
      String(authorization.environment),
    )
  )
    throw new Error("attack.authorization.environment is invalid.");

  const positive = (
    key: "maxRequests" | "timeoutMs" | "rateLimitPerSecond" | "maxConsecutiveServerErrors",
    max: number,
  ) => {
    const raw = attack[key];
    if (
      raw !== undefined &&
      (!Number.isSafeInteger(raw) || Number(raw) < 1 || Number(raw) > max)
    )
      throw new Error(`attack.${key} must be between 1 and ${max}.`);
  };
  positive("maxRequests", 500);
  positive("timeoutMs", 30000);
  positive("rateLimitPerSecond", 20);
  positive("maxConsecutiveServerErrors", 10);

  if (
    attack.allowMutations !== undefined &&
    typeof attack.allowMutations !== "boolean"
  )
    throw new Error("attack.allowMutations must be boolean.");
  if (
    authorization.environment === "production" &&
    attack.allowMutations === true
  )
    throw new Error(
      "REAPER does not allow mutating attack scenarios against production targets.",
    );

  const identities = new Set<string>();
  if (attack.identities !== undefined) {
    if (
      !attack.identities ||
      typeof attack.identities !== "object" ||
      Array.isArray(attack.identities)
    )
      throw new Error("attack.identities must be an object.");
    for (const [name, raw] of Object.entries(
      attack.identities as Record<string, unknown>,
    )) {
      if (!scenarioId.test(name))
        throw new Error(`Invalid attack identity name: ${name}`);
      if (!raw || typeof raw !== "object" || Array.isArray(raw))
        throw new Error(`attack.identities.${name} must be an object.`);
      const identity = raw as Record<string, unknown>;
      for (const key of Object.keys(identity))
        if (!["tokenEnv", "tokenVar"].includes(key))
          throw new Error(`Unknown attack.identities.${name} key: ${key}`);
      for (const key of ["tokenEnv", "tokenVar"])
        if (
          identity[key] !== undefined &&
          (typeof identity[key] !== "string" ||
            !envName.test(String(identity[key])))
        )
          throw new Error(`attack.identities.${name}.${key} is invalid.`);
      if (identity.tokenEnv !== undefined && identity.tokenVar !== undefined)
        throw new Error(
          `attack.identities.${name} cannot use tokenEnv and tokenVar together.`,
        );
      identities.add(name);
    }
  }

  if (!Array.isArray(attack.scenarios) || attack.scenarios.length < 1)
    throw new Error("attack.scenarios must be a non-empty array.");
  if (attack.scenarios.length > 100)
    throw new Error("attack.scenarios cannot exceed 100 entries.");
  const ids = new Set<string>();
  for (const [index, raw] of attack.scenarios.entries()) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw))
      throw new Error(`attack.scenarios[${index}] must be an object.`);
    const item = raw as Record<string, unknown>;
    const keys = new Set(["id", "title", "dimension", "severity", "steps", "cleanup"]);
    for (const key of Object.keys(item))
      if (!keys.has(key))
        throw new Error(`Unknown attack.scenarios[${index}] key: ${key}`);
    if (typeof item.id !== "string" || !scenarioId.test(item.id))
      throw new Error(`attack.scenarios[${index}].id is invalid.`);
    if (ids.has(item.id))
      throw new Error(`Duplicate attack scenario id: ${item.id}`);
    ids.add(item.id);
    if (typeof item.title !== "string" || item.title.trim().length < 3)
      throw new Error(`attack.scenarios[${index}].title is required.`);
    if (
      !["ownership", "tenant", "vertical", "session", "business-logic"].includes(
        String(item.dimension),
      )
    )
      throw new Error(`attack.scenarios[${index}].dimension is invalid.`);
    if (
      item.severity !== undefined &&
      !["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].includes(
        String(item.severity),
      )
    )
      throw new Error(`attack.scenarios[${index}].severity is invalid.`);
    if (!Array.isArray(item.steps) || item.steps.length < 1)
      throw new Error(`attack.scenarios[${index}].steps cannot be empty.`);
    const stepLabel = `attack.scenarios[${index}]`;
    (item.steps as unknown[]).forEach((step, stepIndex) =>
      validateStep(
        step,
        `${stepLabel}.steps[${stepIndex}]`,
        identities,
        attack.allowMutations === true,
      ),
    );
    if (
      ["ownership", "tenant", "vertical"].includes(String(item.dimension))
    ) {
      for (const [stepIndex, rawStep] of (item.steps as unknown[]).entries()) {
        const step = rawStep as Record<string, unknown>;
        const expect = step.expect as Record<string, unknown> | undefined;
        if (expect?.deniedStatuses !== undefined) {
          if (typeof step.actor !== "string" || !identities.has(step.actor))
            throw new Error(
              `${stepLabel}.steps[${stepIndex}] requires a configured actor for confirmed authorization testing.`,
            );
          if (typeof step.resource !== "string" || step.resource.trim().length < 1)
            throw new Error(
              `${stepLabel}.steps[${stepIndex}] requires a known test resource for confirmed authorization testing.`,
            );
        }
      }
    }
    if (
      attack.allowMutations === true &&
      authorization.environment !== "production" &&
      (item.steps as AttackStep[]).some((step) =>
        !["GET", "HEAD"].includes(step.method ?? "GET"),
      ) &&
      (!Array.isArray(item.cleanup) || item.cleanup.length === 0)
    )
      throw new Error(`${stepLabel} mutates state and requires cleanup steps.`);
    if (item.cleanup !== undefined) {
      if (!Array.isArray(item.cleanup))
        throw new Error(`${stepLabel}.cleanup must be an array.`);
      (item.cleanup as unknown[]).forEach((step, stepIndex) =>
        validateStep(
          step,
          `${stepLabel}.cleanup[${stepIndex}]`,
          identities,
          true,
        ),
      );
    }
  }

  return attack as unknown as AttackConfig;
}
