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

CREATE TABLE IF NOT EXISTS reaper_control.execution_envelopes (
  workspace_id uuid NOT NULL REFERENCES reaper_control.workspaces(id) ON DELETE CASCADE,
  job_id uuid NOT NULL,
  run_id uuid NOT NULL,
  worker_id text NOT NULL CHECK (length(worker_id) BETWEEN 1 AND 200),
  envelope jsonb NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, job_id),
  FOREIGN KEY (workspace_id, job_id)
    REFERENCES reaper_control.jobs(workspace_id, id)
    ON DELETE CASCADE,
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
ALTER TABLE reaper_control.execution_envelopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE reaper_control.execution_envelopes FORCE ROW LEVEL SECURITY;
ALTER TABLE reaper_control.audit_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE reaper_control.audit_heads FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS reaper_workspace_boundary ON reaper_control.execution_journals;
CREATE POLICY reaper_workspace_boundary
ON reaper_control.execution_journals
FOR ALL
USING (workspace_id = reaper_control.current_workspace_id())
WITH CHECK (workspace_id = reaper_control.current_workspace_id());

DROP POLICY IF EXISTS reaper_workspace_boundary ON reaper_control.execution_envelopes;
CREATE POLICY reaper_workspace_boundary
ON reaper_control.execution_envelopes
FOR ALL
USING (workspace_id = reaper_control.current_workspace_id())
WITH CHECK (workspace_id = reaper_control.current_workspace_id());

DROP POLICY IF EXISTS reaper_workspace_boundary ON reaper_control.audit_heads;
CREATE POLICY reaper_workspace_boundary
ON reaper_control.audit_heads
FOR ALL
USING (workspace_id = reaper_control.current_workspace_id())
WITH CHECK (workspace_id = reaper_control.current_workspace_id());

CREATE OR REPLACE FUNCTION reaper_control.prepare_platform_execution_envelope(
  p_job_id uuid,
  p_worker_id text,
  p_envelope jsonb,
  p_expires_at timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = reaper_control, pg_temp
AS $prepare$
DECLARE
  v_workspace_id uuid;
  v_run_id uuid;
BEGIN
  IF p_envelope IS NULL OR jsonb_typeof(p_envelope) <> 'object' THEN
    RAISE EXCEPTION 'execution envelope must be a JSON object';
  END IF;
  IF p_expires_at <= now() OR p_expires_at > now() + interval '35 minutes' THEN
    RAISE EXCEPTION 'execution envelope expiry is invalid';
  END IF;

  SELECT workspace_id, run_id
  INTO v_workspace_id, v_run_id
  FROM jobs
  WHERE id = p_job_id
    AND status = 'RUNNING'
    AND worker_id = p_worker_id
    AND lease_expires_at > now()
  FOR UPDATE;

  IF NOT FOUND THEN
    RETURN false;
  END IF;

  INSERT INTO execution_envelopes(
    workspace_id,job_id,run_id,worker_id,envelope,expires_at
  )
  VALUES (
    v_workspace_id,p_job_id,v_run_id,p_worker_id,p_envelope,p_expires_at
  )
  ON CONFLICT (workspace_id,job_id)
  DO UPDATE SET
    run_id = EXCLUDED.run_id,
    worker_id = EXCLUDED.worker_id,
    envelope = EXCLUDED.envelope,
    expires_at = EXCLUDED.expires_at,
    created_at = now();

  RETURN true;
END
$prepare$;

CREATE OR REPLACE FUNCTION reaper_control.load_platform_execution_envelope(
  p_job_id uuid,
  p_worker_id text
)
RETURNS TABLE (
  workspace_id uuid,
  run_id uuid,
  envelope jsonb
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = reaper_control, pg_temp
AS $load$
BEGIN
  RETURN QUERY
  SELECT e.workspace_id, e.run_id, e.envelope
  FROM execution_envelopes e
  JOIN jobs j
    ON j.workspace_id = e.workspace_id
   AND j.id = e.job_id
   AND j.run_id = e.run_id
  WHERE e.job_id = p_job_id
    AND e.worker_id = p_worker_id
    AND e.expires_at > now()
    AND j.status = 'RUNNING'
    AND j.worker_id = p_worker_id
    AND j.lease_expires_at > now();
END
$load$;

CREATE OR REPLACE FUNCTION reaper_control.delete_platform_execution_envelope(
  p_job_id uuid,
  p_worker_id text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = reaper_control, pg_temp
AS $delete$
BEGIN
  DELETE FROM execution_envelopes
  WHERE job_id = p_job_id
    AND worker_id = p_worker_id;

  RETURN FOUND;
END
$delete$;

CREATE OR REPLACE FUNCTION reaper_control.collect_expired_execution_envelopes(
  p_max_deletes integer DEFAULT 100
)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = reaper_control, pg_temp
AS $collect$
DECLARE
  v_deleted integer;
BEGIN
  IF p_max_deletes < 1 OR p_max_deletes > 1000 THEN
    RAISE EXCEPTION 'execution envelope collection limit is invalid';
  END IF;

  WITH expired AS (
    SELECT ctid
    FROM execution_envelopes
    WHERE expires_at <= now()
    ORDER BY expires_at
    LIMIT p_max_deletes
  )
  DELETE FROM execution_envelopes e
  USING expired
  WHERE e.ctid = expired.ctid;

  GET DIAGNOSTICS v_deleted = ROW_COUNT;
  RETURN v_deleted;
END
$collect$;

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

REVOKE ALL ON FUNCTION reaper_control.prepare_platform_execution_envelope(uuid, text, jsonb, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION reaper_control.load_platform_execution_envelope(uuid, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION reaper_control.delete_platform_execution_envelope(uuid, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION reaper_control.collect_expired_execution_envelopes(integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION reaper_control.renew_platform_job_lease(uuid, text, integer) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION reaper_control.lease_platform_job(text, integer)
TO reaper_platform_dispatcher;

GRANT EXECUTE ON FUNCTION reaper_control.fail_platform_job(uuid, text, text, integer)
TO reaper_platform_dispatcher;

GRANT EXECUTE ON FUNCTION reaper_control.prepare_platform_execution_envelope(uuid, text, jsonb, timestamptz)
TO reaper_platform_dispatcher;

GRANT EXECUTE ON FUNCTION reaper_control.collect_expired_execution_envelopes(integer)
TO reaper_platform_dispatcher;

GRANT EXECUTE ON FUNCTION reaper_control.renew_platform_job_lease(uuid, text, integer)
TO reaper_platform_runner;

GRANT EXECUTE ON FUNCTION reaper_control.complete_platform_job(uuid, text, jsonb)
TO reaper_platform_runner;

GRANT EXECUTE ON FUNCTION reaper_control.fail_platform_job(uuid, text, text, integer)
TO reaper_platform_runner;

GRANT EXECUTE ON FUNCTION reaper_control.load_platform_execution_envelope(uuid, text)
TO reaper_platform_runner;

GRANT EXECUTE ON FUNCTION reaper_control.delete_platform_execution_envelope(uuid, text)
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
