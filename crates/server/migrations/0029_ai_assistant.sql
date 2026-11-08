-- BYOK assistant settings, bounded plans and deterministic security findings.
-- These tables arrived with the assistant feature after main's lineage
-- convergence at version 28, so the version is appended rather than folded into
-- a shipped migration. Every create is guarded and the runner tolerates
-- duplicate objects, matching the reconciliation migrations.
CREATE TABLE IF NOT EXISTS ai_settings(org_id TEXT PRIMARY KEY,settings TEXT NOT NULL,key_enc TEXT NOT NULL DEFAULT '',updated_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS ai_plans(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,actor TEXT NOT NULL,operations TEXT NOT NULL,status TEXT NOT NULL,expires_at BIGINT NOT NULL,results TEXT NOT NULL DEFAULT '[]');
CREATE TABLE IF NOT EXISTS folders(id TEXT PRIMARY KEY,env_id TEXT NOT NULL,path TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS idx_folders_env_path ON folders(env_id,path);
CREATE TABLE IF NOT EXISTS integration_drafts(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,env_id TEXT NOT NULL,provider_kind TEXT NOT NULL,name TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS ai_finding_states(org_id TEXT NOT NULL,finding_id TEXT NOT NULL,status TEXT NOT NULL,exception_until BIGINT NOT NULL DEFAULT 0,maintenance_note TEXT NOT NULL DEFAULT '',PRIMARY KEY(org_id,finding_id));
CREATE TABLE IF NOT EXISTS ai_usage(org_id TEXT NOT NULL,day BIGINT NOT NULL,requests BIGINT NOT NULL DEFAULT 0,units BIGINT NOT NULL DEFAULT 0,active_until BIGINT NOT NULL DEFAULT 0,claim TEXT NOT NULL DEFAULT '',PRIMARY KEY(org_id,day));
CREATE TABLE IF NOT EXISTS ai_activity(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,app_id TEXT NOT NULL,env_id TEXT NOT NULL,actor TEXT NOT NULL,credential TEXT NOT NULL,action TEXT NOT NULL,resource TEXT NOT NULL,count BIGINT NOT NULL,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS ai_finding_history(org_id TEXT NOT NULL,finding_id TEXT NOT NULL,finding TEXT NOT NULL,first_seen BIGINT NOT NULL,last_seen BIGINT NOT NULL,PRIMARY KEY(org_id,finding_id));
CREATE INDEX IF NOT EXISTS idx_ai_activity_org ON ai_activity(org_id,created_at);
CREATE INDEX IF NOT EXISTS idx_ai_plans_expiry ON ai_plans(expires_at);
CREATE INDEX IF NOT EXISTS idx_ai_drafts_org ON integration_drafts(org_id);
