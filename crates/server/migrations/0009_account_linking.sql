-- Migration 9: account linking.
-- Frozen history: applied to databases created before the runner tracked
-- checksums. Never edit this file; add a new numbered migration instead.
ALTER TABLE social_states ADD COLUMN link_user TEXT DEFAULT '';
ALTER TABLE oidc_states ADD COLUMN link_user TEXT DEFAULT '';
CREATE TABLE IF NOT EXISTS identity_bindings(issuer TEXT NOT NULL,subject TEXT NOT NULL,user_id TEXT NOT NULL,provider TEXT DEFAULT '',created_at BIGINT NOT NULL,PRIMARY KEY(issuer,subject));
CREATE TABLE IF NOT EXISTS logout_replay(jti TEXT PRIMARY KEY,expires_at BIGINT NOT NULL);
