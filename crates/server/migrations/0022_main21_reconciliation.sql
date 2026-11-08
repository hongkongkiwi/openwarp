ALTER TABLE envs ADD COLUMN max_versions BIGINT DEFAULT 0;
ALTER TABLE leases ADD COLUMN attempted_at BIGINT DEFAULT 0;
ALTER TABLE audit ADD COLUMN seq BIGINT DEFAULT 0;
ALTER TABLE audit ADD COLUMN prev_hash TEXT DEFAULT '';
ALTER TABLE audit ADD COLUMN hash TEXT DEFAULT '';
CREATE TABLE IF NOT EXISTS audit_heads(org_id TEXT PRIMARY KEY,seq BIGINT NOT NULL,hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS wrap_tokens(token_hash TEXT PRIMARY KEY,env_id TEXT NOT NULL,payload_enc TEXT NOT NULL,created_by TEXT DEFAULT '',created_at BIGINT NOT NULL,expires_at BIGINT NOT NULL,used BIGINT DEFAULT 0);
CREATE INDEX IF NOT EXISTS idx_audit_org_seq ON audit(org_id,seq);
CREATE INDEX IF NOT EXISTS idx_wrap_tokens_expiry ON wrap_tokens(expires_at);
ALTER TABLE orgs ADD COLUMN emergency_locked BIGINT NOT NULL DEFAULT 0;
ALTER TABLE apps ADD COLUMN emergency_locked BIGINT NOT NULL DEFAULT 0;
UPDATE envs SET restricted=1 WHERE id IN (SELECT env_id FROM env_members)
  AND NOT EXISTS (SELECT 1 FROM meta WHERE k='migration:env_restricted');
INSERT INTO meta(k,v) SELECT 'migration:env_restricted','0'
  WHERE NOT EXISTS (SELECT 1 FROM meta WHERE k='migration:env_restricted');
CREATE TABLE IF NOT EXISTS change_requests(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,title TEXT NOT NULL,author TEXT NOT NULL,revision BIGINT NOT NULL,status TEXT NOT NULL,approved_by TEXT DEFAULT '',created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS change_request_envs(request_id TEXT NOT NULL,env_id TEXT NOT NULL,payload_enc TEXT NOT NULL,PRIMARY KEY(request_id,env_id));
CREATE TABLE IF NOT EXISTS workload_trusts(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,identity_id TEXT NOT NULL,env_id TEXT NOT NULL,issuer TEXT NOT NULL,audience TEXT NOT NULL,subject TEXT NOT NULL,jwks TEXT NOT NULL,scopes TEXT NOT NULL,ttl BIGINT NOT NULL,bound_claims TEXT NOT NULL,revoked BIGINT DEFAULT 0,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS workload_replay(key TEXT PRIMARY KEY,expires_at BIGINT NOT NULL);
ALTER TABLE tokens ADD COLUMN trust_id TEXT DEFAULT '';
CREATE TABLE IF NOT EXISTS transit_keys(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,name TEXT NOT NULL,current_version BIGINT NOT NULL,UNIQUE(org_id,name));
CREATE TABLE IF NOT EXISTS transit_versions(key_id TEXT NOT NULL,org_id TEXT NOT NULL,version BIGINT NOT NULL,key_enc TEXT NOT NULL,PRIMARY KEY(key_id,version));
