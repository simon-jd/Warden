CREATE TABLE scim_users (
 id text PRIMARY KEY CHECK (id ~ '^[A-Z2-7]{26}$'),
 tenant_id text NOT NULL CHECK (tenant_id <> ''),
 user_name text NOT NULL CHECK (octet_length(user_name) BETWEEN 1 AND 256),
 external_id text NOT NULL CHECK (external_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
 display_name text NOT NULL DEFAULT '' CHECK (octet_length(display_name) <= 256),
 active boolean NOT NULL,
 version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
-- SCIM userName uniqueness is case-insensitive (RFC 7643 section 4.1.1).
CREATE UNIQUE INDEX scim_users_tenant_user_name ON scim_users(tenant_id, lower(user_name));
CREATE UNIQUE INDEX scim_users_tenant_external_id ON scim_users(tenant_id, external_id);
-- Every API request resolves the token's object ID here.
CREATE INDEX scim_users_active_external_id ON scim_users(external_id) WHERE active;
