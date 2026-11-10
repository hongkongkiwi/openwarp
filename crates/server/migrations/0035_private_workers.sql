CREATE TABLE IF NOT EXISTS workers(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,env_id TEXT NOT NULL,name TEXT NOT NULL,target TEXT NOT NULL,pubkey TEXT NOT NULL,cert_serial TEXT DEFAULT '',last_seen BIGINT DEFAULT 0,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS worker_enrollments(token_hash TEXT PRIMARY KEY,worker_id TEXT NOT NULL,expires_at BIGINT NOT NULL,used BIGINT DEFAULT 0);
CREATE TABLE IF NOT EXISTS worker_jobs(id TEXT PRIMARY KEY,worker_id TEXT NOT NULL,env_id TEXT NOT NULL,kind TEXT NOT NULL,payload_enc TEXT NOT NULL,status TEXT DEFAULT 'queued',result_enc TEXT DEFAULT '',lease_id TEXT DEFAULT '',created_at BIGINT NOT NULL,claimed_at BIGINT DEFAULT 0,finished_at BIGINT DEFAULT 0);
CREATE INDEX IF NOT EXISTS idx_workers_env ON workers(env_id,target);
CREATE INDEX IF NOT EXISTS idx_worker_jobs_status ON worker_jobs(worker_id,status);
