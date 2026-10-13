BEGIN;

CREATE INDEX IF NOT EXISTS execution_envelopes_workspace_run_idx
  ON reaper_control.execution_envelopes(workspace_id, run_id);

COMMIT;
