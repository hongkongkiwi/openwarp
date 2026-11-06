-- Migration 12: reuse detection.
-- Frozen history: applied to databases created before the runner tracked
-- checksums. Never edit this file; add a new numbered migration instead.
ALTER TABLE orgs ADD COLUMN reuse_check BIGINT DEFAULT 1;
ALTER TABLE apps ADD COLUMN reuse_check BIGINT DEFAULT 1;
ALTER TABLE secrets ADD COLUMN value_fp TEXT DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_secrets_fp ON secrets(value_fp);
