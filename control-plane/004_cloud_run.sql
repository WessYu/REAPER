BEGIN;

CREATE TABLE IF NOT EXISTS reaper_control.execution_journals (
  workspace_id uuid NOT NULL REFERENCES reaper_control.workspaces(id) ON DELETE CASCADE,
  run_id uuid NOT NULL,
  record jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, run_id),
  FOREIGN KEY (workspace_id, run_id)
    REFERENCES reaper_control.runs(workspace_id, id)
    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS reaper_control.audit_heads (
  workspace_id uuid NOT NULL REFERENCES reaper_control.workspaces(id) ON DELETE CASCADE,
  run_id uuid NOT NULL,
  sequence bigint NOT NULL CHECK (sequence >= 0),
  event_hash text NOT NULL CHECK (event_hash ~ '^[a-f0-9]{64}$'),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, run_id),
  FOREIGN KEY (workspace_id, run_id)
    REFERENCES reaper_control.runs(workspace_id, id)
    ON DELETE CASCADE
);

ALTER TABLE reaper_control.execution_journals ENABLE ROW LEVEL SECURITY;
ALTER TABLE reaper_control.execution_journals FORCE ROW LEVEL SECURITY;
ALTER TABLE reaper_control.audit_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE reaper_control.audit_heads FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS reaper_workspace_boundary ON reaper_control.execution_journals;
CREATE POLICY reaper_workspace_boundary
ON reaper_control.execution_journals
FOR ALL
USING (workspace_id = reaper_control.current_workspace_id())
WITH CHECK (workspace_id = reaper_control.current_workspace_id());

DROP POLICY IF EXISTS reaper_workspace_boundary ON reaper_control.audit_heads;
CREATE POLICY reaper_workspace_boundary
ON reaper_control.audit_heads
FOR ALL
USING (workspace_id = reaper_control.current_workspace_id())
WITH CHECK (workspace_id = reaper_control.current_workspace_id());

CREATE OR REPLACE FUNCTION reaper_control.renew_platform_job_lease(
  p_job_id uuid,
  p_worker_id text,
  p_lease_seconds integer DEFAULT 600
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = reaper_control, pg_temp
AS $$
BEGIN
  IF p_lease_seconds < 60 OR p_lease_seconds > 900 THEN
    RAISE EXCEPTION 'job lease must be between 60 and 900 seconds';
  END IF;

  UPDATE jobs
  SET lease_expires_at = now() + make_interval(secs => p_lease_seconds),
      updated_at = now()
  WHERE id = p_job_id
    AND status = 'RUNNING'
    AND worker_id = p_worker_id
    AND lease_expires_at > now();

  RETURN FOUND;
END
$$;

DO $cloud$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'reaper_platform_dispatcher') THEN
    CREATE ROLE reaper_platform_dispatcher NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'reaper_platform_runner') THEN
    CREATE ROLE reaper_platform_runner NOLOGIN;
  END IF;
END
$cloud$;

GRANT USAGE ON SCHEMA reaper_control
TO reaper_platform_dispatcher, reaper_platform_runner;

REVOKE ALL ON FUNCTION reaper_control.renew_platform_job_lease(uuid, text, integer) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION reaper_control.lease_platform_job(text, integer)
TO reaper_platform_dispatcher;

GRANT EXECUTE ON FUNCTION reaper_control.fail_platform_job(uuid, text, text, integer)
TO reaper_platform_dispatcher;

GRANT EXECUTE ON FUNCTION reaper_control.renew_platform_job_lease(uuid, text, integer)
TO reaper_platform_runner;

GRANT EXECUTE ON FUNCTION reaper_control.complete_platform_job(uuid, text, jsonb)
TO reaper_platform_runner;

GRANT EXECUTE ON FUNCTION reaper_control.fail_platform_job(uuid, text, text, integer)
TO reaper_platform_runner;

GRANT SELECT, INSERT, UPDATE ON
  reaper_control.execution_journals,
  reaper_control.audit_heads
TO reaper_platform_runner;

GRANT SELECT, INSERT ON
  reaper_control.audit_events
TO reaper_platform_runner;

GRANT SELECT, INSERT, DELETE ON
  reaper_control.consumed_scope_nonces
TO reaper_platform_runner;

GRANT SELECT ON reaper_control.runs TO reaper_platform_runner;

COMMIT;
