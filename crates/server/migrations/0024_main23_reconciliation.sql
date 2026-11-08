-- Reconciles the main branch's shipped device version 23 (d39138e).
CREATE TABLE IF NOT EXISTS pki_devices(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,ca_id TEXT NOT NULL,app_id TEXT DEFAULT '',env_id TEXT DEFAULT '',name TEXT NOT NULL,model TEXT DEFAULT '',hardware_serial TEXT DEFAULT '',tags TEXT DEFAULT '',sans TEXT DEFAULT '',cert_days BIGINT DEFAULT 90,active_cert_id TEXT DEFAULT '',enroll_epoch BIGINT DEFAULT 0,deleting BIGINT DEFAULT 0,created_at BIGINT NOT NULL,updated_at BIGINT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS idx_pki_devices_ca_name ON pki_devices(ca_id,name);
CREATE INDEX IF NOT EXISTS idx_pki_devices_org ON pki_devices(org_id);
CREATE INDEX IF NOT EXISTS idx_pki_devices_env ON pki_devices(env_id);
CREATE TABLE IF NOT EXISTS pki_enrollments(id TEXT PRIMARY KEY,device_id TEXT NOT NULL,token_hash TEXT NOT NULL,expires_at BIGINT NOT NULL,used_at BIGINT DEFAULT 0,created_by TEXT DEFAULT '',created_at BIGINT NOT NULL,enroll_epoch BIGINT DEFAULT 0);
CREATE UNIQUE INDEX IF NOT EXISTS idx_pki_enrollments_hash ON pki_enrollments(token_hash);
CREATE INDEX IF NOT EXISTS idx_pki_enrollments_device ON pki_enrollments(device_id);
ALTER TABLE pki_certs ADD COLUMN device_id TEXT DEFAULT '';
ALTER TABLE pki_certs ADD COLUMN revoked_at BIGINT DEFAULT 0;
ALTER TABLE pki_certs ADD COLUMN issued_via TEXT DEFAULT '';
