-- Migration 3: team env grants.
-- Frozen history: applied to databases created before the runner tracked
-- checksums. Never edit this file; add a new numbered migration instead.
CREATE TABLE IF NOT EXISTS team_env_grants(team_id TEXT NOT NULL,env_id TEXT NOT NULL,PRIMARY KEY(team_id,env_id));
