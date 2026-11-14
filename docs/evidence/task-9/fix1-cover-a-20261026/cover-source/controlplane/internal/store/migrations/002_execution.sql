ALTER TABLE runs DROP CONSTRAINT runs_state_check;
ALTER TABLE runs ADD CONSTRAINT runs_state_check CHECK (state IN ('queued','starting','running','succeeded','failed','denied','interrupted'));
ALTER TABLE runs ADD COLUMN result jsonb;
ALTER TABLE runs ADD COLUMN error_code text NOT NULL DEFAULT '';
ALTER TABLE runs ADD COLUMN logs jsonb NOT NULL DEFAULT '{"logs":[],"status":"pending","truncated":false,"dropped_bytes":0}';
ALTER TABLE runs ADD COLUMN cleanup_pending boolean NOT NULL DEFAULT false;
ALTER TABLE runs ADD COLUMN updated_at timestamptz NOT NULL DEFAULT clock_timestamp();
CREATE TABLE run_executions (
 run_id text PRIMARY KEY REFERENCES runs(run_id),
 generation bigint NOT NULL CHECK (generation > 0),
 owner_pid integer NOT NULL,
 runtime_node text NOT NULL,
 claimed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX runs_execution_work ON runs(created_at) WHERE state IN ('queued','starting','running') OR cleanup_pending;
