-- Migration 15: ssh hosts and step up.
-- Frozen history: applied to databases created before the runner tracked
-- checksums. Never edit this file; add a new numbered migration instead.
ALTER TABLE ssh_certs ADD COLUMN cert_type TEXT DEFAULT 'user';
CREATE TABLE IF NOT EXISTS ssh_hosts(id TEXT PRIMARY KEY,ca_id TEXT NOT NULL,hostname TEXT NOT NULL,public_key TEXT NOT NULL,fingerprint TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ssh_hosts_key ON ssh_hosts(ca_id,hostname,fingerprint);
CREATE TABLE IF NOT EXISTS step_up_challenges(challenge_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL,risk TEXT NOT NULL,need_totp BIGINT DEFAULT 0,need_email BIGINT DEFAULT 0,email_code_hash TEXT DEFAULT '',attempts BIGINT DEFAULT 0,created_at BIGINT NOT NULL,expires_at BIGINT NOT NULL,used BIGINT DEFAULT 0);
CREATE TABLE IF NOT EXISTS step_up_grants(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL,risk TEXT NOT NULL,created_at BIGINT NOT NULL,expires_at BIGINT NOT NULL,used BIGINT DEFAULT 0);
