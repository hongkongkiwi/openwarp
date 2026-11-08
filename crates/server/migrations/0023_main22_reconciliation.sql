-- Reconciles the main branch's shipped version 22 (b3eea91). Databases that
-- already carry these objects keep them; pre-merge engine databases gain them.
CREATE TABLE IF NOT EXISTS workload_bindings(identity_id TEXT PRIMARY KEY,org_id TEXT NOT NULL,revision TEXT NOT NULL,issuer TEXT NOT NULL,jwks_url TEXT NOT NULL,audience TEXT NOT NULL,subject TEXT NOT NULL,max_ttl_secs BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS workload_assertions(digest TEXT PRIMARY KEY,expires_at BIGINT NOT NULL);
ALTER TABLE tokens ADD COLUMN workload_revision TEXT DEFAULT '';
CREATE TABLE IF NOT EXISTS path_policies(env_id TEXT NOT NULL,role TEXT NOT NULL,rules TEXT NOT NULL,PRIMARY KEY(env_id,role));
CREATE TABLE IF NOT EXISTS compat_transit_keys(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,name TEXT NOT NULL,wrapping_key TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS idx_compat_transit_keys_name ON compat_transit_keys(org_id,name);
CREATE TABLE IF NOT EXISTS compat_transit_versions(key_id TEXT NOT NULL,version BIGINT NOT NULL,key_enc TEXT NOT NULL,created_at BIGINT NOT NULL,PRIMARY KEY(key_id,version));
ALTER TABLE rotation_schedules ADD COLUMN pending_enc TEXT DEFAULT '';
ALTER TABLE rotation_schedules ADD COLUMN static_target TEXT DEFAULT NULL;
ALTER TABLE rotation_schedules ADD COLUMN execution_token TEXT DEFAULT '';
CREATE UNIQUE INDEX IF NOT EXISTS idx_static_rotation_target ON rotation_schedules(static_target);
INSERT INTO meta(k,v) SELECT 'rotation_lifecycle',''
  WHERE NOT EXISTS (SELECT 1 FROM meta WHERE k='rotation_lifecycle');
