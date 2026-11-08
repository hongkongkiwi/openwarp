-- Migration 16: delegated envs and auth v2.
-- Frozen history: applied to databases created before the runner tracked
-- checksums. Never edit this file; add a new numbered migration instead.
ALTER TABLE envs ADD COLUMN runner_id TEXT DEFAULT '';
ALTER TABLE secrets ADD COLUMN path_enc TEXT DEFAULT '';
ALTER TABLE secrets ADD COLUMN tags_enc TEXT DEFAULT '';
ALTER TABLE secrets ADD COLUMN key_index TEXT DEFAULT '';
ALTER TABLE users ADD COLUMN auth_version BIGINT DEFAULT 1;
ALTER TABLE users ADD COLUMN kdf_salt TEXT DEFAULT '';
ALTER TABLE users ADD COLUMN kdf_iterations BIGINT DEFAULT 0;
ALTER TABLE users ADD COLUMN kdf_algo TEXT DEFAULT '';
ALTER TABLE users ADD COLUMN auth_key_enc TEXT DEFAULT '';
CREATE TABLE IF NOT EXISTS passkeys(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,name TEXT DEFAULT '',credential_id TEXT NOT NULL,credential_json TEXT NOT NULL,sign_count BIGINT DEFAULT 0,created_at BIGINT NOT NULL,last_used_at BIGINT DEFAULT 0);
CREATE TABLE IF NOT EXISTS passkey_registrations(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,state_json TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS mfa_passkey_states(mfa_token TEXT PRIMARY KEY,user_id TEXT NOT NULL,state_json TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS email_codes(user_id TEXT NOT NULL,purpose TEXT NOT NULL,code_hash TEXT NOT NULL,created_at BIGINT NOT NULL,expires_at BIGINT NOT NULL,attempts BIGINT DEFAULT 0,PRIMARY KEY(user_id,purpose));
CREATE TABLE IF NOT EXISTS runners(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,name TEXT NOT NULL,pubkey TEXT NOT NULL,token_hash TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS runner_env_keys(runner_id TEXT NOT NULL,env_id TEXT NOT NULL,wrapped_key TEXT NOT NULL,PRIMARY KEY(runner_id,env_id));
CREATE TABLE IF NOT EXISTS sync_jobs(id TEXT PRIMARY KEY,env_id TEXT NOT NULL,integration_id TEXT NOT NULL,runner_id TEXT NOT NULL,kind TEXT DEFAULT 'sync',status TEXT DEFAULT 'pending',detail TEXT DEFAULT '',created_at BIGINT NOT NULL,claimed_at BIGINT DEFAULT 0,claim_id TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS auth_challenges(id_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL,challenge TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_secrets_key_index ON secrets(env_id,key_index);
CREATE INDEX IF NOT EXISTS idx_passkeys_user ON passkeys(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_passkeys_credential ON passkeys(credential_id);
CREATE INDEX IF NOT EXISTS idx_runners_token ON runners(token_hash);
CREATE INDEX IF NOT EXISTS idx_sync_jobs_pending ON sync_jobs(status,created_at);
CREATE INDEX IF NOT EXISTS idx_sync_jobs_integration ON sync_jobs(integration_id,status);
CREATE INDEX IF NOT EXISTS idx_auth_challenges_user ON auth_challenges(user_id);
