-- Reconciles the main branch's shipped device version 24: CA hierarchy,
-- attestation and device groups.
ALTER TABLE pki_cas ADD COLUMN parent_id TEXT DEFAULT '';
ALTER TABLE pki_cas ADD COLUMN revoked BIGINT DEFAULT 0;
ALTER TABLE pki_cas ADD COLUMN revoked_at BIGINT DEFAULT 0;
ALTER TABLE pki_cas ADD COLUMN hook_url TEXT DEFAULT '';
ALTER TABLE pki_cas ADD COLUMN hook_secret_enc TEXT DEFAULT '';
ALTER TABLE pki_cas ADD COLUMN attest_issuer TEXT DEFAULT '';
ALTER TABLE pki_cas ADD COLUMN attest_key_pem TEXT DEFAULT '';
ALTER TABLE pki_cas ADD COLUMN attest_alg TEXT DEFAULT 'ES256';
ALTER TABLE pki_cas ADD COLUMN attest_required BIGINT DEFAULT 0;
CREATE TABLE IF NOT EXISTS pki_groups(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,ca_id TEXT NOT NULL,name TEXT NOT NULL,env_id TEXT DEFAULT '',sans TEXT DEFAULT '',cert_days BIGINT DEFAULT 90,tags TEXT DEFAULT '',created_at BIGINT NOT NULL,updated_at BIGINT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS idx_pki_groups_ca_name ON pki_groups(ca_id,name);
CREATE INDEX IF NOT EXISTS idx_pki_groups_org ON pki_groups(org_id);
ALTER TABLE pki_devices ADD COLUMN group_id TEXT DEFAULT '';
ALTER TABLE pki_devices ADD COLUMN attested BIGINT DEFAULT 0;
ALTER TABLE pki_devices ADD COLUMN attestation TEXT DEFAULT '';
ALTER TABLE pki_enrollments ADD COLUMN revoke_previous BIGINT DEFAULT 0;
ALTER TABLE pki_enrollments ADD COLUMN nonce TEXT DEFAULT '';
ALTER TABLE pki_cas ADD COLUMN ca_kind TEXT DEFAULT 'root';
UPDATE pki_cas SET ca_kind='intermediate' WHERE parent_id<>'';
UPDATE pki_cas SET kind='x509' WHERE kind='root' OR kind='intermediate';
