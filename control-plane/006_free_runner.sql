BEGIN;

CREATE OR REPLACE FUNCTION reaper_control.lease_free_platform_job(
  p_worker_id text,
  p_lease_seconds integer DEFAULT 300
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
AS $free$
DECLARE
  v_job jobs%ROWTYPE;
BEGIN
  IF p_worker_id IS NULL OR length(p_worker_id) < 1 OR length(p_worker_id) > 200 THEN
    RAISE EXCEPTION 'worker id is invalid';
  END IF;
  IF p_lease_seconds < 60 OR p_lease_seconds > 600 THEN
    RAISE EXCEPTION 'free runner lease must be between 60 and 600 seconds';
  END IF;

  SELECT j.*
  INTO v_job
  FROM jobs AS j
  JOIN runs AS r
    ON r.workspace_id = j.workspace_id
   AND r.id = j.run_id
  WHERE (
      (
        j.status = 'PENDING'
        AND j.available_at <= now()
      ) OR (
        j.status = 'RUNNING'
        AND j.lease_expires_at <= now()
        AND j.attempt < 3
      )
    )
    AND r.environment IN ('preview', 'staging')
    AND r.target_origin LIKE 'https://%'
    AND r.config_path = 'free-readonly.ts'
    AND r.permissions = '["read"]'::jsonb
    AND COALESCE((r.limits->>'maxRequests')::integer, 8) <= 8
    AND COALESCE((r.limits->>'maxCleanupRequests')::integer, 1) <= 1
    AND COALESCE((r.limits->>'rateLimitPerSecond')::integer, 2) <= 2
    AND COALESCE((r.limits->>'deadlineMs')::integer, 60000) <= 60000
  ORDER BY j.created_at
  FOR UPDATE OF j SKIP LOCKED
  LIMIT 1;

  IF NOT FOUND THEN
    RETURN;
  END IF;

  UPDATE jobs
  SET status = 'RUNNING',
      attempt = jobs.attempt + 1,
      worker_id = p_worker_id,
      lease_expires_at = now() + make_interval(secs => p_lease_seconds),
      updated_at = now(),
      error = NULL
  WHERE jobs.id = v_job.id;

  PERFORM set_config('reaper.workspace_id', v_job.workspace_id::text, true);
  PERFORM set_config('reaper.principal_id', 'reaper-free-runner', true);

  UPDATE runs
  SET status = 'RUNNING',
      error = NULL,
      updated_at = now()
  WHERE runs.id = v_job.run_id
    AND runs.workspace_id = v_job.workspace_id;

  RETURN QUERY
  SELECT j.id, j.workspace_id, j.run_id, j.attempt, j.payload, j.lease_expires_at
  FROM jobs j
  WHERE j.id = v_job.id;
END
$free$;

REVOKE ALL ON FUNCTION reaper_control.lease_free_platform_job(text, integer)
FROM PUBLIC;

COMMIT;
