-- Migration 4: instance leases.
-- Frozen history: applied to databases created before the runner tracked
-- checksums. Never edit this file; add a new numbered migration instead.
CREATE TABLE IF NOT EXISTS instance_leases(name TEXT PRIMARY KEY,owner TEXT NOT NULL,expires_at BIGINT NOT NULL);
