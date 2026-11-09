ALTER TABLE sessions ADD COLUMN id TEXT DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_sessions_id ON sessions(id);
