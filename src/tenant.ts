export type WorkspaceRole = "viewer" | "analyst" | "admin";

export type WorkspaceAction =
  | "readFindings"
  | "runAssessment"
  | "manageProject"
  | "manageMembers"
  | "administerWorkspace";

export interface Organization {
  id: string;
  name: string;
}

export interface Workspace {
  id: string;
  organizationId: string;
  name: string;
}

export interface Project {
  id: string;
  workspaceId: string;
  name: string;
}

export interface Assessment {
  id: string;
  workspaceId: string;
  projectId: string;
  reference: string;
}

export interface CommercialRun {
  id: string;
  workspaceId: string;
  projectId: string;
  assessmentId: string;
}

export interface CommercialFinding {
  id: string;
  workspaceId: string;
  runId: string;
  ruleId: string;
}

export interface WorkspaceMembership {
  principalId: string;
  workspaceId: string;
  role: WorkspaceRole;
}

export interface WorkspaceAuthorizationContext {
  principalId: string;
  workspaceId: string;
  role: WorkspaceRole;
}

const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/;

const permissions: Record<WorkspaceRole, ReadonlySet<WorkspaceAction>> = {
  viewer: new Set(["readFindings"]),
  analyst: new Set(["readFindings", "runAssessment", "manageProject"]),
  admin: new Set([
    "readFindings",
    "runAssessment",
    "manageProject",
    "manageMembers",
    "administerWorkspace",
  ]),
};

export function assertCommercialId(value: string, label = "id"): string {
  if (typeof value !== "string" || !ID.test(value))
    throw new Error(`Commercial domain ${label} is invalid.`);
  return value;
}

export function authorizeWorkspaceAction(
  principalId: string,
  requestedWorkspaceId: string,
  memberships: readonly WorkspaceMembership[],
  action: WorkspaceAction,
): WorkspaceAuthorizationContext {
  assertCommercialId(principalId, "principalId");
  assertCommercialId(requestedWorkspaceId, "workspaceId");
  if (
    ![
      "readFindings",
      "runAssessment",
      "manageProject",
      "manageMembers",
      "administerWorkspace",
    ].includes(action)
  )
    throw new Error("Workspace action is invalid.");

  const membership = memberships.find(
    (candidate) =>
      candidate.principalId === principalId &&
      candidate.workspaceId === requestedWorkspaceId,
  );
  if (!membership) throw new Error("Workspace access denied.");
  if (!["viewer", "analyst", "admin"].includes(membership.role))
    throw new Error("Workspace role is invalid.");
  if (!permissions[membership.role].has(action))
    throw new Error("Workspace action is not permitted for this role.");

  return {
    principalId,
    workspaceId: requestedWorkspaceId,
    role: membership.role,
  };
}

export function assertWorkspaceEntity(
  authorization: WorkspaceAuthorizationContext,
  entityWorkspaceId: string,
): void {
  assertCommercialId(entityWorkspaceId, "entity workspaceId");
  if (authorization.workspaceId !== entityWorkspaceId)
    throw new Error("Cross-workspace access denied.");
}
