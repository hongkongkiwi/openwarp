CREATE TABLE deleted_env_receipts(token_id TEXT PRIMARY KEY,token_hash TEXT NOT NULL UNIQUE,created_by TEXT NOT NULL,org_id TEXT NOT NULL,app_id TEXT NOT NULL,env_id TEXT NOT NULL,env_name TEXT NOT NULL,app_name TEXT NOT NULL,workspace_name TEXT NOT NULL,scopes TEXT NOT NULL,original_expires_at BIGINT NOT NULL,deleted_at BIGINT NOT NULL,expires_at BIGINT NOT NULL,kind TEXT NOT NULL,trust_id TEXT NOT NULL,workload_revision TEXT NOT NULL,restricted BIGINT NOT NULL);
CREATE INDEX deleted_env_receipts_app ON deleted_env_receipts(app_id);
CREATE INDEX deleted_env_receipts_org ON deleted_env_receipts(org_id);
CREATE INDEX deleted_env_receipts_creator ON deleted_env_receipts(created_by);
