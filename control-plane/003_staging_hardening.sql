BEGIN;

ALTER FUNCTION reaper_control.current_workspace_id()
  SET search_path = reaper_control, pg_temp;

ALTER FUNCTION reaper_control.current_principal_id()
  SET search_path = reaper_control, pg_temp;

DROP POLICY IF EXISTS reaper_organization_bootstrap_insert
ON reaper_control.organizations;
CREATE POLICY reaper_organization_bootstrap_insert
ON reaper_control.organizations
FOR INSERT
WITH CHECK ((SELECT current_setting('reaper.bootstrap', true)) = '1');

CREATE INDEX IF NOT EXISTS workspaces_organization_id_idx
  ON reaper_control.workspaces(organization_id);

CREATE INDEX IF NOT EXISTS assessments_workspace_project_idx
  ON reaper_control.assessments(workspace_id, project_id);

CREATE INDEX IF NOT EXISTS runs_workspace_project_idx
  ON reaper_control.runs(workspace_id, project_id);

CREATE INDEX IF NOT EXISTS runs_workspace_assessment_idx
  ON reaper_control.runs(workspace_id, assessment_id);

CREATE INDEX IF NOT EXISTS findings_workspace_idx
  ON reaper_control.findings(workspace_id);

CREATE INDEX IF NOT EXISTS findings_workspace_run_idx
  ON reaper_control.findings(workspace_id, run_id);

CREATE INDEX IF NOT EXISTS jobs_workspace_run_idx
  ON reaper_control.jobs(workspace_id, run_id);

COMMIT;
