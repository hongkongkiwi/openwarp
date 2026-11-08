-- Bring databases created by older binaries up to the consolidated baseline.
-- Applied tolerantly: a fresh database already has every column here.
ALTER TABLE envs ADD COLUMN mode TEXT DEFAULT 'sse';
ALTER TABLE envs ADD COLUMN restricted BIGINT DEFAULT 0;
ALTER TABLE envs ADD COLUMN require_approval BIGINT DEFAULT 0;
ALTER TABLE secrets ADD COLUMN e2e BIGINT DEFAULT 0;
ALTER TABLE secrets ADD COLUMN deleted_at BIGINT DEFAULT 0;
ALTER TABLE users ADD COLUMN active BIGINT DEFAULT 1;
ALTER TABLE tokens ADD COLUMN kind TEXT DEFAULT 'human';
ALTER TABLE tokens ADD COLUMN expires_at BIGINT DEFAULT 0;
ALTER TABLE leases ADD COLUMN username TEXT DEFAULT '';
ALTER TABLE leases ADD COLUMN config_enc TEXT DEFAULT '';
ALTER TABLE oidc_states ADD COLUMN nonce TEXT DEFAULT '';
ALTER TABLE pki_cas ADD COLUMN serial TEXT DEFAULT '';
ALTER TABLE rotation_schedules ADD COLUMN path TEXT DEFAULT '/';
ALTER TABLE rotation_schedules ADD COLUMN config_enc TEXT DEFAULT '';
ALTER TABLE users ADD COLUMN email_verified BIGINT DEFAULT 1;
