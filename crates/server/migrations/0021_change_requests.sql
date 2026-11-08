CREATE TABLE IF NOT EXISTS change_requests(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,title TEXT NOT NULL,author TEXT NOT NULL,revision BIGINT NOT NULL,status TEXT NOT NULL,approved_by TEXT DEFAULT '',created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS change_request_envs(request_id TEXT NOT NULL,env_id TEXT NOT NULL,payload_enc TEXT NOT NULL,PRIMARY KEY(request_id,env_id));
