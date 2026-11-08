-- Migration 14: ssh ca.
-- Frozen history: applied to databases created before the runner tracked
-- checksums. Never edit this file; add a new numbered migration instead.
ALTER TABLE pki_cas ADD COLUMN kind TEXT DEFAULT 'x509';
ALTER TABLE pki_cas ADD COLUMN allow_forwarding BIGINT DEFAULT 0;
CREATE TABLE IF NOT EXISTS ssh_principal_grants(ca_id TEXT NOT NULL,role TEXT NOT NULL,principals TEXT NOT NULL,max_ttl BIGINT DEFAULT 900,PRIMARY KEY(ca_id,role));
CREATE TABLE IF NOT EXISTS ssh_certs(id TEXT PRIMARY KEY,ca_id TEXT NOT NULL,key_id TEXT NOT NULL,principal TEXT NOT NULL,public_key TEXT NOT NULL,cert TEXT NOT NULL,serial BIGINT NOT NULL,actor TEXT NOT NULL,revoked BIGINT DEFAULT 0,valid_after BIGINT NOT NULL,valid_before BIGINT NOT NULL,created_at BIGINT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_ssh_certs_ca ON ssh_certs(ca_id,created_at);
CREATE INDEX IF NOT EXISTS idx_ssh_grants_ca ON ssh_principal_grants(ca_id);
