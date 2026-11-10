-- Migration 2: token scopes.
-- Frozen history: applied to databases created before the runner tracked
-- checksums. Never edit this file; add a new numbered migration instead.
ALTER TABLE tokens ADD COLUMN scopes TEXT DEFAULT '';
ALTER TABLE tokens ADD COLUMN last_used_at BIGINT DEFAULT 0;
