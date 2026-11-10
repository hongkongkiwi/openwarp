CREATE TABLE IF NOT EXISTS broker_services(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,revision BIGINT NOT NULL,config TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS broker_sessions(id TEXT PRIMARY KEY,token_hash TEXT NOT NULL UNIQUE,org_id TEXT NOT NULL,service_id TEXT NOT NULL,revision BIGINT NOT NULL,subject_user_id TEXT NOT NULL,issuer_user_id TEXT NOT NULL,capabilities TEXT NOT NULL,approvals TEXT NOT NULL,expires_at BIGINT NOT NULL,revoked BIGINT NOT NULL DEFAULT 0,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS broker_audit(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,env_id TEXT NOT NULL,service_id TEXT NOT NULL,session_id TEXT NOT NULL,subject_user_id TEXT NOT NULL,issuer_user_id TEXT NOT NULL,capability TEXT NOT NULL,decision TEXT NOT NULL,status BIGINT NOT NULL,duration_ms BIGINT NOT NULL,created_at BIGINT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_broker_services_org ON broker_services(org_id);
CREATE INDEX IF NOT EXISTS idx_broker_sessions_org ON broker_sessions(org_id,created_at);
CREATE INDEX IF NOT EXISTS idx_broker_audit_org ON broker_audit(org_id,created_at);
