-- Team service schema. Run as a dedicated application database owner.
CREATE TABLE IF NOT EXISTS team_cases (
  case_id text PRIMARY KEY,
  title text NOT NULL,
  purpose text NOT NULL,
  authority text NOT NULL,
  target_type text NOT NULL,
  target text NOT NULL,
  sensitivity text NOT NULL CHECK (sensitivity IN ('internal','confidential','restricted')),
  retention_until date NOT NULL,
  owner_sub text NOT NULL,
  legal_hold boolean NOT NULL DEFAULT false,
  hold_reason text NOT NULL DEFAULT '',
  hold_authority text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);
CREATE TABLE IF NOT EXISTS team_members (
  case_id text NOT NULL REFERENCES team_cases(case_id),
  subject text NOT NULL,
  role text NOT NULL CHECK (role IN ('viewer','analyst','reviewer','owner')),
  granted_by text NOT NULL,
  granted_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (case_id, subject)
);
CREATE TABLE IF NOT EXISTS team_objects (
  object_id text PRIMARY KEY,
  case_id text NOT NULL REFERENCES team_cases(case_id),
  kind text NOT NULL CHECK (kind IN ('artifact','job-result','report')),
  filename text NOT NULL,
  content_type text NOT NULL,
  sha256 text NOT NULL CHECK (length(sha256)=64),
  size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);
CREATE INDEX IF NOT EXISTS team_objects_case_idx ON team_objects(case_id);
CREATE TABLE IF NOT EXISTS team_annotations (
  annotation_id text PRIMARY KEY,
  case_id text NOT NULL REFERENCES team_cases(case_id),
  body text NOT NULL,
  author_sub text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS team_work_items (
  work_id text PRIMARY KEY,
  case_id text NOT NULL REFERENCES team_cases(case_id),
  title text NOT NULL,
  status text NOT NULL CHECK (status IN ('open','in-review','resolved')),
  assigned_to text,
  created_by text NOT NULL,
  updated_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS team_jobs (
  job_id text PRIMARY KEY,
  case_id text NOT NULL REFERENCES team_cases(case_id),
  kind text NOT NULL CHECK (kind IN ('provider','media')),
  provider text,
  target text,
  source_object_id text,
  options jsonb NOT NULL DEFAULT '{}'::jsonb,
  status text NOT NULL CHECK (status IN ('pending','approved','running','completed','failed','rejected')),
  requested_by text NOT NULL,
  reviewed_by text,
  review_reason text NOT NULL DEFAULT '',
  result_object_id text,
  error text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS team_jobs_queue_idx ON team_jobs(status, created_at);
CREATE TABLE IF NOT EXISTS team_reports (
  report_id text PRIMARY KEY,
  case_id text NOT NULL REFERENCES team_cases(case_id),
  version integer NOT NULL CHECK (version > 0),
  object_id text NOT NULL REFERENCES team_objects(object_id),
  status text NOT NULL CHECK (status IN ('draft','approved','rejected')),
  created_by text NOT NULL,
  reviewed_by text,
  review_reason text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  reviewed_at timestamptz,
  UNIQUE(case_id, version)
);
CREATE TABLE IF NOT EXISTS team_audit (
  event_id bigserial PRIMARY KEY,
  case_id text,
  actor_sub text NOT NULL,
  action text NOT NULL,
  resource_id text NOT NULL,
  details jsonb NOT NULL,
  created_at text NOT NULL,
  previous_sha256 text NOT NULL,
  event_sha256 text NOT NULL
);
CREATE OR REPLACE FUNCTION team_audit_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'team_audit is append-only';
END $$;
DROP TRIGGER IF EXISTS team_audit_no_mutation ON team_audit;
CREATE TRIGGER team_audit_no_mutation BEFORE UPDATE OR DELETE OR TRUNCATE ON team_audit
  FOR EACH STATEMENT EXECUTE FUNCTION team_audit_immutable();
