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
  | "Active Security";
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
export type AttackEnvironment = "local" | "preview" | "staging" | "production";
export interface AttackScope {
  authorized: boolean;
  authorizationId?: string;
  expiresAt?: string;
  environment: AttackEnvironment;
  allowedTargets?: string[];
  pathPrefixes?: string[];
  allowProduction?: boolean;
}
export interface AttackIdentity {
  authEnv?: string;
  authVar?: string;
  cookieEnv?: string;
  cookieVar?: string;
  role?: string;
  tenant?: string;
}
export interface AttackStep {
  name: string;
  path: string;
  method?: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE";
  identity?: string;
  headers?: Record<string, string>;
  body?: VerifyJson;
  expectStatus?: number;
  capture?: Record<string, string>;
}
export interface AttackExpectation {
  statuses?: number[];
  headers?: Record<string, string>;
  absentHeaders?: string[];
}
export type AttackScenarioKind =
  | "bola"
  | "tenant"
  | "privilege"
  | "authorization"
  | "session"
  | "cors"
  | "csrf"
  | "business";
export interface AttackScenario {
  name: string;
  kind: AttackScenarioKind;
  attackerIdentity: string;
  ownerIdentity?: string;
  setup?: AttackStep[];
  attack: AttackStep;
  cleanup?: AttackStep[];
  denyStatuses?: number[];
  expect?: AttackExpectation;
  resource?: string;
  sourceFindingId?: string;
}
export interface AttackConfig {
  scope: AttackScope;
  maxRequests?: number;
  maxMutationRequests?: number;
  timeoutMs?: number;
  rateLimitPerSecond?: number;
  maxServerErrors?: number;
  allowMutations?: boolean;
  identities: Record<string, AttackIdentity>;
  scenarios: AttackScenario[];
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
  kind: "route" | "query" | "resource" | "principal" | "request" | "finding";
  label: string;
}
export interface GraphEdge {
  from: string;
  to: string;
  relation: "calls" | "accesses" | "tests" | "owns" | "correlates" | "observed";
}
export interface AttackAuditEvent {
  sequence: number;
  scenario: string;
  step: string;
  identity?: string;
  method: string;
  path: string;
  status?: number;
  durationMs: number;
  phase: "setup" | "attack" | "cleanup";
  previousHash: string;
  hash: string;
}
export interface AttackScenarioResult {
  name: string;
  kind: AttackScenarioKind;
  status: "passed" | "confirmed" | "incomplete";
  findingId?: string;
}
export interface AttackSummary {
  target: string;
  environment: AttackEnvironment;
  authorizationId?: string;
  configHash: string;
  startedAt: string;
  requestCount: number;
  mutationCount: number;
  serverErrors: number;
  auditHash: string;
  scenarios: AttackScenarioResult[];
  audit: AttackAuditEvent[];
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
  attack?: AttackSummary;
}
export const severities: Severity[] = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFO",
];
