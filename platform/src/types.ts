export type PlatformRole = "viewer" | "analyst" | "admin";

export interface RequestContext {
  principalId: string;
  workspaceId: string;
  role: PlatformRole;
  apiKeyId: string;
}

export interface IssuedApiKey {
  id: string;
  token: string;
  expiresAt: string | null;
}

export interface CreateProjectInput {
  name: string;
}

export interface CreateAssessmentInput {
  projectId: string;
  reference: string;
}

export interface CreateRunInput {
  projectId: string;
  assessmentId: string;
  targetOrigin: string;
  environment: "local" | "preview" | "staging" | "production";
  configPath: string;
  permissions?: Array<
    "read" | "mutations" | "syntheticIdentities" | "internalNetwork"
  >;
  limits?: {
    maxRequests?: number;
    maxCleanupRequests?: number;
    rateLimitPerSecond?: number;
    deadlineMs?: number;
  };
}

export interface PlatformJob {
  id: string;
  workspaceId: string;
  runId: string;
  status: "PENDING" | "RUNNING" | "COMPLETED" | "FAILED";
  attempt: number;
  availableAt: string;
  leaseExpiresAt: string | null;
  payload: CreateRunInput;
}
