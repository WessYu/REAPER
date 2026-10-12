export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type Confidence = "CONFIRMED" | "HIGH" | "MEDIUM" | "LOW";
export type Category =
  | "SQL Safety"
  | "Authorization"
  | "Tenant Isolation"
  | "RLS"
  | "Privileges"
  | "Supabase"
  | "Migrations"
  | "Secrets & Crypto"
  | "Runtime Verification"
  | "Offensive Validation";
export interface Location {
  file: string;
  line: number;
  column: number;
}
export interface Evidence extends Location {
  kind: "source" | "propagation" | "sink";
  label: string;
}
export interface Finding extends Location {
  id: string;
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: Confidence;
  category: Category;
  cwe?: number;
  route?: string;
  resource?: string;
  evidence: string[];
  dataFlow: Evidence[];
  recommendation: string;
  fingerprint: string;
  status: "new" | "baseline" | "suppressed";
  suppression?: string;
}
export interface Resource {
  ownership?: string[];
  tenant?: string[];
  sensitive?: string[];
}
export type VerifyJson =
  | string
  | number
  | boolean
  | null
  | VerifyJson[]
  | { [key: string]: VerifyJson };
export interface VerifyAssertion {
  name: string;
  path: string;
  method?: "GET" | "HEAD";
  expectStatus: number;
  authEnv?: string;
  authVar?: string;
  dimension?: "ownership" | "tenant" | "anonymous";
}
export interface VerifyLifecycleRequest {
  name: string;
  path: string;
  method: "POST" | "PUT" | "PATCH" | "DELETE";
  expectStatus?: number;
  authEnv?: string;
  authVar?: string;
  body?: VerifyJson;
  capture?: Record<string, string>;
}
export interface VerifySyntheticUsers {
  count?: number;
  path: string;
  method?: "POST" | "PUT";
  body: VerifyJson;
  expectStatus?: number;
  tokenPath: string;
  idPath?: string;
  cleanup?: {
    path: string;
    method?: "DELETE";
    expectStatus?: number;
  };
}
export interface VerifyConfig {
  allowedTargets?: string[];
  maxRequests?: number;
  concurrency?: number;
  timeoutMs?: number;
  rateLimitPerSecond?: number;
  discoverOpenApi?: boolean;
  openApiPaths?: string[];
  probeDiscovered?: boolean;
  discoveryAuthEnv?: string;
  allowMutations?: boolean;
  syntheticUsers?: VerifySyntheticUsers;
  setup?: VerifyLifecycleRequest[];
  teardown?: VerifyLifecycleRequest[];
  assertions: VerifyAssertion[];
}
export type AttackDimension =
  | "ownership"
  | "tenant"
  | "vertical"
  | "session"
  | "business-logic";

export interface AttackAuthorization {
  acknowledged: true;
  reference: string;
  environment: "local" | "preview" | "staging" | "production";
}

export interface AttackIdentity {
  tokenEnv?: string;
  tokenVar?: string;
}

export interface AttackExpectation {
  deniedStatuses?: number[];
  allowedStatuses?: number[];
  jsonEquals?: Record<string, string | number | boolean | null>;
}

export interface AttackStep {
  name: string;
  path: string;
  method?: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE";
  actor?: string;
  body?: VerifyJson;
  expect?: AttackExpectation;
  capture?: Record<string, string>;
  resource?: string;
}

export interface AttackScenario {
  id: string;
  title: string;
  dimension: AttackDimension;
  severity?: Severity;
  steps: AttackStep[];
  cleanup?: AttackStep[];
}

export interface AttackMatrixResource {
  id: string;
  owner: string;
  label?: string;
}

export interface AttackMatrix {
  id: string;
  title: string;
  dimension: "ownership" | "tenant";
  severity?: Severity;
  method?: "GET" | "HEAD";
  path: string;
  actors: string[];
  resources: AttackMatrixResource[];
  deniedStatuses: number[];
}

export interface AttackConfig {
  allowedTargets: string[];
  authorization: AttackAuthorization;
  maxRequests?: number;
  timeoutMs?: number;
  rateLimitPerSecond?: number;
  maxConsecutiveServerErrors?: number;
  allowMutations?: boolean;
  identities?: Record<string, AttackIdentity>;
  scenarios?: AttackScenario[];
  matrices?: AttackMatrix[];
}

export interface AttackAuditEvent {
  scenarioId: string;
  step: string;
  actor?: string;
  method: string;
  path: string;
  status?: number;
  durationMs: number;
  outcome:
    | "passed"
    | "confirmed"
    | "inconclusive"
    | "error"
    | "cleanup"
    | "cleanup-error";
}

export interface AttackRunMetadata {
  runId: string;
  target: string;
  authorizationReference: string;
  environment: AttackAuthorization["environment"];
  startedAt: string;
  completedAt: string;
  requests: number;
  cleanupFailures: number;
  confirmed: Array<{ scenarioId: string; findingId: string }>;
  audit: AttackAuditEvent[];
}

export interface MiddlewareContract {
  establishes: string[];
}
export interface Config {
  resources?: Record<string, Resource>;
  principalPaths?: string[];
  middleware?: Record<string, MiddlewareContract>;
  exclude?: string[];
  maxFiles?: number;
  maxFileBytes?: number;
  verify?: VerifyConfig;
  attack?: AttackConfig;
}
export interface Diagnostic extends Partial<Location> {
  message: string;
}
export interface GraphNode {
  id: string;
  kind: "route" | "query" | "resource" | "principal" | "finding";
  label: string;
}
export interface GraphEdge {
  from: string;
  to: string;
  relation: "calls" | "accesses" | "acts-as" | "targets" | "confirms";
}
export interface ScanResult {
  version: "0.2.0";
  root: string;
  findings: Finding[];
  diagnostics: Diagnostic[];
  graph: { nodes: GraphNode[]; edges: GraphEdge[] };
  metrics: {
    files: number;
    routes: number;
    sinks: number;
    durationMs: number;
    memoryBytes: number;
  };
  coverage: { source: boolean; database: boolean; runtime: boolean };
  attack?: AttackRunMetadata;
}
export const severities: Severity[] = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFO",
];
