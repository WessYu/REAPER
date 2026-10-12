import type { AttackConfig, AttackStep, VerifyJson } from "./model.js";

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
        Number.isSafeInteger(status) &&
        Number(status) >= 100 &&
        Number(status) <= 599,
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
      if (
        ![
          "deniedStatuses",
          "allowedStatuses",
          "confirmStatuses",
          "jsonEquals",
        ].includes(key)
      )
        throw new Error(`Unknown ${label}.expect key: ${key}`);
    const denied = statusList(
      expect.deniedStatuses,
      `${label}.expect.deniedStatuses`,
    );
    const allowedStatuses = statusList(
      expect.allowedStatuses,
      `${label}.expect.allowedStatuses`,
    );
    const confirmStatuses = statusList(
      expect.confirmStatuses,
      `${label}.expect.confirmStatuses`,
    );
    if (denied && allowedStatuses)
      throw new Error(
        `${label}.expect cannot define both deniedStatuses and allowedStatuses.`,
      );
    if (confirmStatuses && !denied)
      throw new Error(
        `${label}.expect.confirmStatuses requires deniedStatuses.`,
      );
    if (!denied && !allowedStatuses)
      throw new Error(`${label}.expect requires a status policy.`);
    if (expect.jsonEquals !== undefined) {
      if (
        !expect.jsonEquals ||
        typeof expect.jsonEquals !== "object" ||
        Array.isArray(expect.jsonEquals) ||
        !Object.entries(expect.jsonEquals as Record<string, unknown>).every(
          ([path, expected]) =>
            path.length > 0 &&
            (expected === null ||
              typeof expected === "string" ||
              typeof expected === "number" ||
              typeof expected === "boolean"),
        )
      )
        throw new Error(
          `${label}.expect.jsonEquals must map JSON paths to scalar literal values.`,
        );
    }
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
    "allowPrivateNetwork",
    "identities",
    "scenarios",
    "matrices",
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
    if (
      !["acknowledged", "reference", "environment", "expiresAt"].includes(key)
    )
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
  if (authorization.expiresAt !== undefined) {
    if (
      typeof authorization.expiresAt !== "string" ||
      !Number.isFinite(Date.parse(authorization.expiresAt))
    )
      throw new Error(
        "attack.authorization.expiresAt must be an ISO-8601 date-time.",
      );
    if (Date.parse(authorization.expiresAt) <= Date.now())
      throw new Error("attack authorization has expired.");
  }
  if (
    authorization.environment === "production" &&
    authorization.expiresAt === undefined
  )
    throw new Error(
      "production attack authorization requires attack.authorization.expiresAt.",
    );

  const positive = (
    key:
      | "maxRequests"
      | "timeoutMs"
      | "rateLimitPerSecond"
      | "maxConsecutiveServerErrors",
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

  for (const key of ["allowMutations", "allowPrivateNetwork"])
    if (attack[key] !== undefined && typeof attack[key] !== "boolean")
      throw new Error(`attack.${key} must be boolean.`);
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

  if (
    attack.scenarios !== undefined &&
    (!Array.isArray(attack.scenarios) || attack.scenarios.length < 1)
  )
    throw new Error(
      "attack.scenarios must be a non-empty array when provided.",
    );
  if (Array.isArray(attack.scenarios) && attack.scenarios.length > 100)
    throw new Error("attack.scenarios cannot exceed 100 entries.");
  if (
    attack.matrices !== undefined &&
    (!Array.isArray(attack.matrices) || attack.matrices.length < 1)
  )
    throw new Error("attack.matrices must be a non-empty array when provided.");
  if (!Array.isArray(attack.scenarios) && !Array.isArray(attack.matrices))
    throw new Error("attack requires scenarios or matrices.");
  const ids = new Set<string>();
  for (const [index, raw] of (attack.scenarios ?? []).entries()) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw))
      throw new Error(`attack.scenarios[${index}] must be an object.`);
    const item = raw as Record<string, unknown>;
    const keys = new Set([
      "id",
      "title",
      "dimension",
      "severity",
      "steps",
      "cleanup",
    ]);
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
      ![
        "ownership",
        "tenant",
        "vertical",
        "session",
        "business-logic",
      ].includes(String(item.dimension))
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
    if (["ownership", "tenant", "vertical"].includes(String(item.dimension))) {
      for (const [stepIndex, rawStep] of (item.steps as unknown[]).entries()) {
        const step = rawStep as Record<string, unknown>;
        const expect = step.expect as Record<string, unknown> | undefined;
        if (expect?.deniedStatuses !== undefined) {
          if (typeof step.actor !== "string" || !identities.has(step.actor))
            throw new Error(
              `${stepLabel}.steps[${stepIndex}] requires a configured actor for confirmed authorization testing.`,
            );
          if (
            typeof step.resource !== "string" ||
            step.resource.trim().length < 1
          )
            throw new Error(
              `${stepLabel}.steps[${stepIndex}] requires a known test resource for confirmed authorization testing.`,
            );
        }
      }
    }
    if (
      attack.allowMutations === true &&
      authorization.environment !== "production" &&
      (item.steps as AttackStep[]).some(
        (step) => !["GET", "HEAD"].includes(step.method ?? "GET"),
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
          attack.allowMutations === true,
        ),
      );
    }
  }

  for (const [index, raw] of (attack.matrices ?? []).entries()) {
    const label = `attack.matrices[${index}]`;
    if (!raw || typeof raw !== "object" || Array.isArray(raw))
      throw new Error(`${label} must be an object.`);
    const item = raw as Record<string, unknown>;
    const keys = new Set([
      "id",
      "title",
      "dimension",
      "severity",
      "method",
      "path",
      "actors",
      "resources",
      "deniedStatuses",
      "confirmStatuses",
      "jsonEquals",
    ]);
    for (const key of Object.keys(item))
      if (!keys.has(key)) throw new Error(`Unknown ${label} key: ${key}`);
    if (typeof item.id !== "string" || !scenarioId.test(item.id))
      throw new Error(`${label}.id is invalid.`);
    if (ids.has(item.id))
      throw new Error(`Duplicate attack scenario/matrix id: ${item.id}`);
    ids.add(item.id);
    if (typeof item.title !== "string" || item.title.trim().length < 3)
      throw new Error(`${label}.title is required.`);
    if (!["ownership", "tenant"].includes(String(item.dimension)))
      throw new Error(`${label}.dimension must be ownership or tenant.`);
    if (
      item.severity !== undefined &&
      !["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].includes(
        String(item.severity),
      )
    )
      throw new Error(`${label}.severity is invalid.`);
    if (
      item.method !== undefined &&
      !["GET", "HEAD"].includes(String(item.method))
    )
      throw new Error(`${label}.method must be GET or HEAD.`);
    if (
      typeof item.path !== "string" ||
      !item.path.startsWith("/") ||
      item.path.startsWith("//") ||
      !item.path.includes("{{RESOURCE_ID}}")
    )
      throw new Error(
        `${label}.path must be origin-relative and contain {{RESOURCE_ID}}.`,
      );
    if (!strings(item.actors))
      throw new Error(`${label}.actors must be a non-empty string array.`);
    for (const actor of item.actors)
      if (!identities.has(actor))
        throw new Error(
          `${label}.actors references unknown identity ${actor}.`,
        );
    if (
      !Array.isArray(item.resources) ||
      item.resources.length < 2 ||
      item.resources.length > 20
    )
      throw new Error(`${label}.resources must contain 2 to 20 resources.`);
    for (const [resourceIndex, rawResource] of item.resources.entries()) {
      if (
        !rawResource ||
        typeof rawResource !== "object" ||
        Array.isArray(rawResource)
      )
        throw new Error(
          `${label}.resources[${resourceIndex}] must be an object.`,
        );
      const resource = rawResource as Record<string, unknown>;
      for (const key of Object.keys(resource))
        if (!["id", "owner", "label"].includes(key))
          throw new Error(
            `Unknown ${label}.resources[${resourceIndex}] key: ${key}`,
          );
      if (typeof resource.id !== "string" || resource.id.length < 1)
        throw new Error(`${label}.resources[${resourceIndex}].id is required.`);
      if (typeof resource.owner !== "string" || !identities.has(resource.owner))
        throw new Error(
          `${label}.resources[${resourceIndex}].owner must reference a configured identity.`,
        );
      if (
        resource.label !== undefined &&
        (typeof resource.label !== "string" || resource.label.length < 1)
      )
        throw new Error(
          `${label}.resources[${resourceIndex}].label must be non-empty.`,
        );
    }
    statusList(item.deniedStatuses, `${label}.deniedStatuses`);
    statusList(item.confirmStatuses, `${label}.confirmStatuses`);
    if (item.jsonEquals !== undefined) {
      if (
        !item.jsonEquals ||
        typeof item.jsonEquals !== "object" ||
        Array.isArray(item.jsonEquals) ||
        !Object.entries(item.jsonEquals as Record<string, unknown>).every(
          ([path, expected]) =>
            path.length > 0 &&
            (expected === null ||
              typeof expected === "string" ||
              typeof expected === "number" ||
              typeof expected === "boolean"),
        )
      )
        throw new Error(
          `${label}.jsonEquals must map JSON paths to scalar literal values.`,
        );
    }
    if (
      (item.actors as string[]).length * (item.resources as unknown[]).length >
      100
    )
      throw new Error(`${label} exceeds the 100-combination matrix cap.`);
  }

  return attack as unknown as AttackConfig;
}
