BEGIN;

ALTER TABLE reaper_control.runs
  ADD COLUMN IF NOT EXISTS environment text
    CHECK (environment IN ('local', 'preview', 'staging', 'production')),
  ADD COLUMN IF NOT EXISTS config_path text
    CHECK (config_path IS NULL OR length(config_path) BETWEEN 1 AND 1024),
  ADD COLUMN IF NOT EXISTS permissions jsonb NOT NULL DEFAULT '["read"]'::jsonb,
  ADD COLUMN IF NOT EXISTS limits jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS report jsonb,
  ADD COLUMN IF NOT EXISTS error text;

CREATE TABLE IF NOT EXISTS reaper_control.api_keys (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES reaper_control.workspaces(id) ON DELETE CASCADE,
  principal_id text NOT NULL CHECK (length(principal_id) BETWEEN 1 AND 200),
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  secret_hash text NOT NULL CHECK (secret_hash ~ '^[a-f0-9]{64}$'),
  expires_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  UNIQUE (id, secret_hash)
);

CREATE INDEX IF NOT EXISTS api_keys_principal_idx
  ON reaper_control.api_keys(workspace_id, principal_id)
  WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS reaper_control.jobs (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES reaper_control.workspaces(id) ON DELETE CASCADE,
  run_id uuid NOT NULL,
  status text NOT NULL CHECK (status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED')),
  attempt integer NOT NULL DEFAULT 0 CHECK (attempt >= 0 AND attempt <= 10),
  available_at timestamptz NOT NULL DEFAULT now(),
  lease_expires_at timestamptz,
  worker_id text CHECK (worker_id IS NULL OR length(worker_id) BETWEEN 1 AND 200),
  payload jsonb NOT NULL,
  error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  FOREIGN KEY (workspace_id, run_id)
    REFERENCES reaper_control.runs(workspace_id, id)
    ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS jobs_available_idx
  ON reaper_control.jobs(status, available_at, created_at)
  WHERE status IN ('PENDING', 'RUNNING');

ALTER TABLE reaper_control.api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE reaper_control.jobs ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS reaper_api_key_workspace ON reaper_control.api_keys;
CREATE POLICY reaper_api_key_workspace
ON reaper_control.api_keys
FOR SELECT
USING (workspace_id = reaper_control.current_workspace_id());

DROP POLICY IF EXISTS reaper_job_workspace ON reaper_control.jobs;
CREATE POLICY reaper_job_workspace
ON reaper_control.jobs
FOR ALL
USING (workspace_id = reaper_control.current_workspace_id())
WITH CHECK (workspace_id = reaper_control.current_workspace_id());

CREATE OR REPLACE FUNCTION reaper_control.authenticate_api_key(
  p_key_id uuid,
  p_secret_hash text
)
RETURNS TABLE (
  api_key_id uuid,
  workspace_id uuid,
  principal_id text,
  role text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = reaper_control, pg_temp
AS $$
DECLARE
  v_key api_keys%ROWTYPE;
BEGIN
  SELECT *
  INTO v_key
  FROM api_keys
  WHERE id = p_key_id
    AND secret_hash = p_secret_hash
    AND revoked_at IS NULL
    AND (expires_at IS NULL OR expires_at > now());

  IF NOT FOUND THEN
    RETURN;
  END IF;

  PERFORM set_config('reaper.workspace_id', v_key.workspace_id::text, true);
  PERFORM set_config('reaper.principal_id', v_key.principal_id, true);

  RETURN QUERY
  UPDATE api_keys k
  SET last_used_at = now()
  FROM workspace_members m
  WHERE k.id = v_key.id
    AND m.workspace_id = v_key.workspace_id
    AND m.principal_id = v_key.principal_id
  RETURNING k.id, k.workspace_id, k.principal_id, m.role;
END
$$;

CREATE OR REPLACE FUNCTION reaper_control.bootstrap_platform(
  p_organization_id uuid,
  p_organization_name text,
  p_workspace_id uuid,
  p_workspace_name text,
  p_principal_id text,
  p_key_id uuid,
  p_key_name text,
  p_secret_hash text,
  p_expires_at timestamptz DEFAULT NULL
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = reaper_control, pg_temp
AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM api_keys) THEN
    RAISE EXCEPTION 'platform bootstrap is already complete';
  END IF;

  INSERT INTO organizations(id, name)
  VALUES (p_organization_id, p_organization_name);

  INSERT INTO workspaces(id, organization_id, name)
  VALUES (p_workspace_id, p_organization_id, p_workspace_name);

  INSERT INTO workspace_members(workspace_id, principal_id, role)
  VALUES (p_workspace_id, p_principal_id, 'admin');

  INSERT INTO api_keys(
    id, workspace_id, principal_id, name, secret_hash, expires_at
  )
  VALUES (
    p_key_id, p_workspace_id, p_principal_id, p_key_name, p_secret_hash, p_expires_at
  );
END
$$;

CREATE OR REPLACE FUNCTION reaper_control.create_api_key(
  p_key_id uuid,
  p_principal_id text,
  p_name text,
  p_secret_hash text,
  p_expires_at timestamptz DEFAULT NULL
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = reaper_control, pg_temp
AS $$
DECLARE
  v_workspace_id uuid := reaper_control.current_workspace_id();
  v_actor text := reaper_control.current_principal_id();
BEGIN
  IF v_workspace_id IS NULL OR v_actor IS NULL THEN
    RAISE EXCEPTION 'workspace authorization context is required';
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM workspace_members
    WHERE workspace_id = v_workspace_id
      AND principal_id = v_actor
      AND role = 'admin'
  ) THEN
    RAISE EXCEPTION 'admin role is required';
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM workspace_members
    WHERE workspace_id = v_workspace_id
      AND principal_id = p_principal_id
  ) THEN
    RAISE EXCEPTION 'API key principal must be a workspace member';
  END IF;

  INSERT INTO api_keys(
    id, workspace_id, principal_id, name, secret_hash, expires_at
  )
  VALUES (
    p_key_id, v_workspace_id, p_principal_id, p_name, p_secret_hash, p_expires_at
  );
END
$$;

CREATE OR REPLACE FUNCTION reaper_control.revoke_api_key(p_key_id uuid)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = reaper_control, pg_temp
AS $$
DECLARE
  v_workspace_id uuid := reaper_control.current_workspace_id();
  v_actor text := reaper_control.current_principal_id();
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM workspace_members
    WHERE workspace_id = v_workspace_id
      AND principal_id = v_actor
      AND role = 'admin'
  ) THEN
    RAISE EXCEPTION 'admin role is required';
  END IF;

  UPDATE api_keys
  SET revoked_at = COALESCE(revoked_at, now())
  WHERE id = p_key_id
    AND workspace_id = v_workspace_id;

  RETURN FOUND;
END
$$;

CREATE OR REPLACE FUNCTION reaper_control.lease_platform_job(
  p_worker_id text,
  p_lease_seconds integer DEFAULT 60
)
RETURNS TABLE (
  id uuid,
  workspace_id uuid,
  run_id uuid,
  attempt integer,
  payload jsonb,
  lease_expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = reaper_control, pg_temp
AS $$
DECLARE
  v_job jobs%ROWTYPE;
BEGIN
  IF p_worker_id IS NULL OR length(p_worker_id) < 1 OR length(p_worker_id) > 200 THEN
    RAISE EXCEPTION 'worker id is invalid';
  END IF;
  IF p_lease_seconds < 15 OR p_lease_seconds > 900 THEN
    RAISE EXCEPTION 'job lease must be between 15 and 900 seconds';
  END IF;

  SELECT *
  INTO v_job
  FROM jobs
  WHERE (
      status = 'PENDING'
      AND available_at <= now()
    ) OR (
      status = 'RUNNING'
      AND lease_expires_at <= now()
      AND attempt < 10
    )
  ORDER BY created_at
  FOR UPDATE SKIP LOCKED
  LIMIT 1;

  IF NOT FOUND THEN
    RETURN;
  END IF;

  UPDATE jobs
  SET status = 'RUNNING',
      attempt = attempt + 1,
      worker_id = p_worker_id,
      lease_expires_at = now() + make_interval(secs => p_lease_seconds),
      updated_at = now()
  WHERE jobs.id = v_job.id;

  PERFORM set_config('reaper.workspace_id', v_job.workspace_id::text, true);
  PERFORM set_config('reaper.principal_id', 'reaper-platform-worker', true);

  UPDATE runs
  SET status = 'RUNNING', updated_at = now()
  WHERE runs.id = v_job.run_id
    AND runs.workspace_id = v_job.workspace_id;

  RETURN QUERY
  SELECT j.id, j.workspace_id, j.run_id, j.attempt, j.payload, j.lease_expires_at
  FROM jobs j
  WHERE j.id = v_job.id;
END
$$;

CREATE OR REPLACE FUNCTION reaper_control.complete_platform_job(
  p_job_id uuid,
  p_worker_id text,
  p_report jsonb
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = reaper_control, pg_temp
AS $$
DECLARE
  v_workspace_id uuid;
  v_run_id uuid;
BEGIN
  UPDATE jobs
  SET status = 'COMPLETED',
      lease_expires_at = NULL,
      updated_at = now(),
      error = NULL
  WHERE id = p_job_id
    AND status = 'RUNNING'
    AND worker_id = p_worker_id
    AND lease_expires_at > now()
  RETURNING workspace_id, run_id INTO v_workspace_id, v_run_id;

  IF NOT FOUND THEN
    RETURN false;
  END IF;

  PERFORM set_config('reaper.workspace_id', v_workspace_id::text, true);
  PERFORM set_config('reaper.principal_id', 'reaper-platform-worker', true);

  UPDATE runs
  SET status = 'COMPLETED',
      report = p_report,
      error = NULL,
      updated_at = now()
  WHERE id = v_run_id AND workspace_id = v_workspace_id;

  RETURN true;
END
$$;

CREATE OR REPLACE FUNCTION reaper_control.fail_platform_job(
  p_job_id uuid,
  p_worker_id text,
  p_error text,
  p_retry_delay_seconds integer DEFAULT 0
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = reaper_control, pg_temp
AS $$
DECLARE
  v_workspace_id uuid;
  v_run_id uuid;
  v_attempt integer;
  v_retry boolean;
BEGIN
  IF p_retry_delay_seconds < 0 OR p_retry_delay_seconds > 3600 THEN
    RAISE EXCEPTION 'retry delay is invalid';
  END IF;

  SELECT workspace_id, run_id, attempt
  INTO v_workspace_id, v_run_id, v_attempt
  FROM jobs
  WHERE id = p_job_id
    AND status = 'RUNNING'
    AND worker_id = p_worker_id
    AND lease_expires_at > now()
  FOR UPDATE;

  IF NOT FOUND THEN
    RETURN false;
  END IF;

  v_retry := v_attempt < 3 AND p_retry_delay_seconds > 0;

  UPDATE jobs
  SET status = CASE WHEN v_retry THEN 'PENDING' ELSE 'FAILED' END,
      available_at = CASE
        WHEN v_retry THEN now() + make_interval(secs => p_retry_delay_seconds)
        ELSE available_at
      END,
      lease_expires_at = NULL,
      updated_at = now(),
      error = left(p_error, 4000)
  WHERE id = p_job_id;

  PERFORM set_config('reaper.workspace_id', v_workspace_id::text, true);
  PERFORM set_config('reaper.principal_id', 'reaper-platform-worker', true);

  UPDATE runs
  SET status = CASE WHEN v_retry THEN 'PENDING' ELSE 'FAILED' END,
      error = left(p_error, 4000),
      updated_at = now()
  WHERE id = v_run_id AND workspace_id = v_workspace_id;

  RETURN true;
END
$$;

DO $
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'reaper_platform_api') THEN
    CREATE ROLE reaper_platform_api NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'reaper_platform_worker') THEN
    CREATE ROLE reaper_platform_worker NOLOGIN;
  END IF;
END
$;

GRANT USAGE ON SCHEMA reaper_control TO reaper_platform_api, reaper_platform_worker;

GRANT SELECT ON
  reaper_control.projects,
  reaper_control.assessments,
  reaper_control.runs,
  reaper_control.findings,
  reaper_control.audit_events,
  reaper_control.api_keys
TO reaper_platform_api;

GRANT INSERT ON
  reaper_control.projects,
  reaper_control.assessments,
  reaper_control.runs,
  reaper_control.jobs
TO reaper_platform_api;

REVOKE ALL ON FUNCTION reaper_control.bootstrap_platform(
  uuid, text, uuid, text, text, uuid, text, text, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION reaper_control.authenticate_api_key(uuid, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION reaper_control.create_api_key(uuid, text, text, text, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION reaper_control.revoke_api_key(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION reaper_control.lease_platform_job(text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION reaper_control.complete_platform_job(uuid, text, jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION reaper_control.fail_platform_job(uuid, text, text, integer) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION reaper_control.authenticate_api_key(uuid, text) TO reaper_platform_api;
GRANT EXECUTE ON FUNCTION reaper_control.create_api_key(uuid, text, text, text, timestamptz) TO reaper_platform_api;
GRANT EXECUTE ON FUNCTION reaper_control.revoke_api_key(uuid) TO reaper_platform_api;
GRANT EXECUTE ON FUNCTION reaper_control.lease_platform_job(text, integer) TO reaper_platform_worker;
GRANT EXECUTE ON FUNCTION reaper_control.complete_platform_job(uuid, text, jsonb) TO reaper_platform_worker;
GRANT EXECUTE ON FUNCTION reaper_control.fail_platform_job(uuid, text, text, integer) TO reaper_platform_worker;

COMMIT;
