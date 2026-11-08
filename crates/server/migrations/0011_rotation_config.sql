-- Migration 11: rotation config.
-- Frozen history: applied to databases created before the runner tracked
-- checksums. Never edit this file; add a new numbered migration instead.
ALTER TABLE rotation_schedules ADD COLUMN config_enc TEXT DEFAULT '';
