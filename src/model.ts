export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type Confidence = "CONFIRMED" | "HIGH" | "MEDIUM" | "LOW";
export type Category =
  | "SQL Safety"
  | "Authorization"
  | "Tenant Isolation"
  | "RLS"
  | "Privileges";
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
export interface Config {
  resources?: Record<string, Resource>;
  principalPaths?: string[];
  exclude?: string[];
  maxFiles?: number;
  maxFileBytes?: number;
}
export interface Diagnostic extends Partial<Location> {
  message: string;
}
export interface GraphNode {
  id: string;
  kind: "route" | "query" | "resource";
  label: string;
}
export interface GraphEdge {
  from: string;
  to: string;
  relation: "calls" | "accesses";
}
export interface ScanResult {
  version: "0.1.0";
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
  coverage: { source: boolean; database: boolean; runtime: false };
}
export const severities: Severity[] = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFO",
];
