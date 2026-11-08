ALTER TABLE sessions ADD COLUMN id TEXT DEFAULT '';
CREATE INDEX idx_sessions_id ON sessions(id);
