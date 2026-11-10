-- Migration 13: secret version paths.
-- Frozen history: applied to databases created before the runner tracked
-- checksums. Never edit this file; add a new numbered migration instead.
ALTER TABLE secret_versions ADD COLUMN path TEXT DEFAULT '/';
ALTER TABLE secret_versions ADD COLUMN tags TEXT DEFAULT '';
