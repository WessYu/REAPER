import { test } from "node:test";
import assert from "node:assert/strict";
import {
  assertWorkspaceEntity,
  authorizeWorkspaceAction,
} from "../dist/index.js";

const memberships = [
  { principalId: "alice", workspaceId: "workspace-a", role: "analyst" },
  { principalId: "bob", workspaceId: "workspace-b", role: "viewer" },
  { principalId: "carol", workspaceId: "workspace-a", role: "admin" },
];

test("workspace authorization denies cross-tenant membership spoofing", () => {
  assert.equal(
    authorizeWorkspaceAction(
      "alice",
      "workspace-a",
      memberships,
      "readFindings",
    ).role,
    "analyst",
  );
  assert.throws(
    () =>
      authorizeWorkspaceAction(
        "alice",
        "workspace-b",
        memberships,
        "readFindings",
      ),
    /access denied/,
  );
  assert.throws(
    () =>
      authorizeWorkspaceAction(
        "bob",
        "workspace-a",
        memberships,
        "readFindings",
      ),
    /access denied/,
  );
});

test("workspace roles deny by default outside their explicit permissions", () => {
  assert.throws(
    () =>
      authorizeWorkspaceAction(
        "bob",
        "workspace-b",
        memberships,
        "runAssessment",
      ),
    /not permitted/,
  );
  assert.throws(
    () =>
      authorizeWorkspaceAction(
        "alice",
        "workspace-a",
        memberships,
        "manageMembers",
      ),
    /not permitted/,
  );
  assert.equal(
    authorizeWorkspaceAction(
      "carol",
      "workspace-a",
      memberships,
      "administerWorkspace",
    ).role,
    "admin",
  );
});

test("authorized context cannot be reused for a foreign workspace entity", () => {
  const context = authorizeWorkspaceAction(
    "alice",
    "workspace-a",
    memberships,
    "readFindings",
  );
  assert.doesNotThrow(() => assertWorkspaceEntity(context, "workspace-a"));
  assert.throws(
    () => assertWorkspaceEntity(context, "workspace-b"),
    /Cross-workspace access denied/,
  );
});
