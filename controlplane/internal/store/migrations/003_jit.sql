CREATE SEQUENCE jit_reconcile_order;
CREATE TABLE jit_requests (
 id text PRIMARY KEY CHECK (id ~ '^[A-Z2-7]{26}$'),
 tenant_id text NOT NULL CHECK (tenant_id <> ''),
 requester text NOT NULL CHECK (octet_length(requester) BETWEEN 1 AND 256),
 role_alias text NOT NULL CHECK (role_alias <> ''),
 reason text NOT NULL CHECK (octet_length(reason) BETWEEN 1 AND 2048),
 duration_ns bigint NOT NULL CHECK (duration_ns > 0 AND duration_ns <= 7200000000000),
 created_at timestamptz NOT NULL,
 approver text,
 approved_at timestamptz,
 expires_at timestamptz,
 namespace text,
 role_name text,
 subject text,
 binding_name text NOT NULL UNIQUE,
 binding_uid text,
 binding_version text,
 state text NOT NULL CHECK (state IN ('requested','grant_pending','active','revoke_pending','expired')),
 last_error text NOT NULL DEFAULT '',
 grant_confirmed boolean NOT NULL DEFAULT false,
 reconcile_order bigint NOT NULL DEFAULT 0 CHECK (reconcile_order >= 0),
 CHECK (approver IS NULL OR approver <> requester),
 CHECK ((approved_at IS NULL) = (expires_at IS NULL)),
 CHECK (expires_at IS NULL OR (expires_at >= approved_at AND expires_at <= approved_at + interval '2 hours')),
 CHECK (state = 'requested' OR (approver IS NOT NULL AND approved_at IS NOT NULL AND namespace IS NOT NULL AND role_name IS NOT NULL AND subject IS NOT NULL)),
 CHECK ((binding_uid IS NULL) = (binding_version IS NULL)),
 CHECK (state <> 'active' OR (binding_uid IS NOT NULL AND binding_version IS NOT NULL AND grant_confirmed)),
 CHECK (NOT grant_confirmed OR state IN ('active','revoke_pending','expired'))
);
CREATE INDEX jit_pending_expiry ON jit_requests(tenant_id, reconcile_order, expires_at, id)
 WHERE state IN ('grant_pending','active','revoke_pending');
