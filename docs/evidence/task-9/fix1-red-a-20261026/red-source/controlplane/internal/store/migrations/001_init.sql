CREATE TABLE runs (
 run_id text PRIMARY KEY CHECK (run_id ~ '^[A-Z2-7]{26}$'),
 tenant_id text NOT NULL CHECK (tenant_id <> ''),
 idempotency_key text NOT NULL CHECK (octet_length(idempotency_key) BETWEEN 1 AND 256),
 canonical_spec bytea NOT NULL,
 state text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE (tenant_id, idempotency_key)
);
CREATE INDEX runs_tenant_id ON runs(tenant_id, run_id);
CREATE TABLE audit_head (
 singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
 last_seq bigint NOT NULL CHECK (last_seq >= 0),
 last_hash bytea NOT NULL CHECK (octet_length(last_hash) = 32)
);
INSERT INTO audit_head(singleton,last_seq,last_hash) VALUES(true,0,decode(repeat('00',32),'hex'));
CREATE TABLE audit_entries (
 seq bigint PRIMARY KEY CHECK (seq > 0),
 canonical_event bytea NOT NULL,
 prev_hash bytea NOT NULL CHECK (octet_length(prev_hash)=32),
 hash bytea NOT NULL CHECK (octet_length(hash)=32)
);
CREATE FUNCTION reject_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'audit_entries is append-only' USING ERRCODE='55000'; END;
$$;
CREATE TRIGGER audit_no_mutation BEFORE UPDATE OR DELETE ON audit_entries
 FOR EACH ROW EXECUTE FUNCTION reject_audit_mutation();
CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON audit_entries
 FOR EACH STATEMENT EXECUTE FUNCTION reject_audit_mutation();
