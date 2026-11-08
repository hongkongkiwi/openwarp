-- Reconciles the main branch's shipped device version 25: renewal challenges,
-- expiry deliveries and TPM columns.
CREATE TABLE IF NOT EXISTS pki_renew_challenges(id TEXT PRIMARY KEY,device_id TEXT NOT NULL,cert_id TEXT NOT NULL,csr TEXT NOT NULL,challenge TEXT NOT NULL,expires_at BIGINT NOT NULL,used_at BIGINT DEFAULT 0);
CREATE INDEX IF NOT EXISTS idx_pki_renew_expiry ON pki_renew_challenges(expires_at);
CREATE TABLE IF NOT EXISTS pki_expiry_deliveries(org_id TEXT NOT NULL,user_id TEXT NOT NULL,day BIGINT NOT NULL,status TEXT NOT NULL,PRIMARY KEY(org_id,user_id,day));
ALTER TABLE pki_devices ADD COLUMN tpm_ak_public TEXT DEFAULT '';
ALTER TABLE pki_devices ADD COLUMN tpm_pcr_digest TEXT DEFAULT '';
ALTER TABLE pki_cas ADD COLUMN attest_mode TEXT DEFAULT 'jwt';
