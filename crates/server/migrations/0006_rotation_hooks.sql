-- Migration 6: rotation hooks.
-- Frozen history: applied to databases created before the runner tracked
-- checksums. Never edit this file; add a new numbered migration instead.
CREATE TABLE IF NOT EXISTS rotation_hooks(org_id TEXT PRIMARY KEY,url TEXT NOT NULL,secret_enc TEXT DEFAULT '',created_at BIGINT NOT NULL);
