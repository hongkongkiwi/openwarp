-- Migration 8: live events.
-- Frozen history: applied to databases created before the runner tracked
-- checksums. Never edit this file; add a new numbered migration instead.
CREATE TABLE IF NOT EXISTS live_events(id BIGINT PRIMARY KEY,org_id TEXT NOT NULL,app_id TEXT DEFAULT '',env_id TEXT DEFAULT '',action TEXT NOT NULL,detail TEXT DEFAULT '',created_at BIGINT NOT NULL);
