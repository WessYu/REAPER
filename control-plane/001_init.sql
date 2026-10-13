BEGIN;

CREATE SCHEMA IF NOT EXISTS reaper_control;

CREATE OR REPLACE FUNCTION reaper_control.current_workspace_id()
RETURNS uuid
LANGUAGE sql
STABLE
AS $$
  SELECT CASE
    WHEN current_setting('reaper.workspace_id', true) IS NULL
      OR current_setting('reaper.workspace_id', true) = ''
    THEN NULL
    ELSE current_setting('reaper.workspace_id', true)::uuid
  END
$$;

CREATE OR REPLACE FUNCTION reaper_control.current_principal_id()
RETURNS text
LANGUAGE sql
STABLE
AS $$
  SELECT NULLIF(current_setting('reaper.principal_id', true), '')
$$;

CREATE TABLE IF NOT EXISTS reaper_control.organizations (
  id uuid PRIMARY KEY,
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS reaper_control.workspaces (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES reaper_control.organizations(id) ON DELETE CASCADE,
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS reaper_control.workspace_members (
  workspace_id uuid NOT NULL REFERENCES reaper_control.workspaces(id) ON DELETE CASCADE,
  principal_id text NOT NULL CHECK (length(principal_id) BETWEEN 1 AND 200),
  role text NOT NULL CHECK (role IN ('viewer', 'analyst', 'admin')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, principal_id)
);

CREATE TABLE IF NOT EXISTS reaper_control.projects (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES reaper_control.workspaces(id) ON DELETE CASCADE,
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id)
);

CREATE TABLE IF NOT EXISTS reaper_control.assessments (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES reaper_control.workspaces(id) ON DELETE CASCADE,
  project_id uuid NOT NULL,
  reference text NOT NULL CHECK (length(reference) BETWEEN 1 AND 200),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  FOREIGN KEY (workspace_id, project_id)
    REFERENCES reaper_control.projects(workspace_id, id)
    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS reaper_control.runs (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES reaper_control.workspaces(id) ON DELETE CASCADE,
  project_id uuid NOT NULL,
  assessment_id uuid NOT NULL,
  status text NOT NULL CHECK (
    status IN (
      'PENDING',
      'RUNNING',
      'CLEANING',
      'COMPLETED',
      'INTERRUPTED',
      'CLEANUP_FAILED',
      'FAILED'
    )
  ),
  target_origin text NOT NULL CHECK (length(target_origin) BETWEEN 1 AND 2048),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  FOREIGN KEY (workspace_id, project_id)
    REFERENCES reaper_control.projects(workspace_id, id)
    ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, assessment_id)
    REFERENCES reaper_control.assessments(workspace_id, id)
    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS reaper_control.findings (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES reaper_control.workspaces(id) ON DELETE CASCADE,
  run_id uuid NOT NULL,
  rule_id text NOT NULL CHECK (length(rule_id) BETWEEN 1 AND 200),
  severity text NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
  payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (workspace_id, run_id)
    REFERENCES reaper_control.runs(workspace_id, id)
    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS reaper_control.audit_events (
  workspace_id uuid NOT NULL REFERENCES reaper_control.workspaces(id) ON DELETE CASCADE,
  run_id uuid NOT NULL,
  sequence bigint NOT NULL CHECK (sequence > 0),
  previous_hash text NOT NULL CHECK (previous_hash ~ '^[a-f0-9]{64}$'),
  event_hash text NOT NULL CHECK (event_hash ~ '^[a-f0-9]{64}$'),
  event_type text NOT NULL CHECK (length(event_type) BETWEEN 1 AND 100),
  payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, run_id, sequence),
  UNIQUE (workspace_id, run_id, event_hash),
  FOREIGN KEY (workspace_id, run_id)
    REFERENCES reaper_control.runs(workspace_id, id)
    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS reaper_control.consumed_scope_nonces (
  workspace_id uuid NOT NULL REFERENCES reaper_control.workspaces(id) ON DELETE CASCADE,
  issuer text NOT NULL CHECK (length(issuer) BETWEEN 1 AND 200),
  assessment_id text NOT NULL CHECK (length(assessment_id) BETWEEN 1 AND 200),
  nonce text NOT NULL CHECK (length(nonce) BETWEEN 1 AND 200),
  target_origin text NOT NULL CHECK (length(target_origin) BETWEEN 1 AND 2048),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, issuer, assessment_id, nonce, target_origin)
);

ALTER TABLE reaper_control.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE reaper_control.organizations FORCE ROW LEVEL SECURITY;
ALTER TABLE reaper_control.workspaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE reaper_control.workspaces FORCE ROW LEVEL SECURITY;

DO $$
DECLARE
  table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'workspace_members',
    'projects',
    'assessments',
    'runs',
    'findings',
    'audit_events',
    'consumed_scope_nonces'
  ]
  LOOP
    EXECUTE format('ALTER TABLE reaper_control.%I ENABLE ROW LEVEL SECURITY', table_name);
    EXECUTE format('ALTER TABLE reaper_control.%I FORCE ROW LEVEL SECURITY', table_name);
  END LOOP;
END
$$;

DROP POLICY IF EXISTS reaper_workspace_self ON reaper_control.workspaces;
CREATE POLICY reaper_workspace_self
ON reaper_control.workspaces
FOR ALL
USING (id = reaper_control.current_workspace_id())
WITH CHECK (id = reaper_control.current_workspace_id());

DROP POLICY IF EXISTS reaper_organization_workspace ON reaper_control.organizations;
CREATE POLICY reaper_organization_workspace
ON reaper_control.organizations
FOR SELECT
USING (
  EXISTS (
    SELECT 1
    FROM reaper_control.workspaces w
    WHERE w.id = reaper_control.current_workspace_id()
      AND w.organization_id = organizations.id
  )
);

DO $$
DECLARE
  table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'workspace_members',
    'projects',
    'assessments',
    'runs',
    'findings',
    'audit_events',
    'consumed_scope_nonces'
  ]
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS reaper_workspace_boundary ON reaper_control.%I', table_name);
    EXECUTE format(
      'CREATE POLICY reaper_workspace_boundary ON reaper_control.%I FOR ALL USING (workspace_id = reaper_control.current_workspace_id()) WITH CHECK (workspace_id = reaper_control.current_workspace_id())',
      table_name
    );
  END LOOP;
END
$$;

COMMIT;
