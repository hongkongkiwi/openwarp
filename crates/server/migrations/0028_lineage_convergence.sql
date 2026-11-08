-- Full convergence for every shipped lineage: engine 23, main 23..27 and the
-- device branch whose ledger rows 17..22 hold device-era DDL. Main's version 26
-- replayed this set unguarded; here every create is guarded and column adds rely
-- on duplicate tolerance, so a database keeping any object is left unchanged.
-- The canonical bootstrap columns, startup index set and the lifecycle meta
-- guard close objects main's old runner installed outside the numbered history.
CREATE TABLE IF NOT EXISTS change_requests(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,title TEXT NOT NULL,author TEXT NOT NULL,revision BIGINT NOT NULL,status TEXT NOT NULL,approved_by TEXT DEFAULT '',created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS change_request_envs(request_id TEXT NOT NULL,env_id TEXT NOT NULL,payload_enc TEXT NOT NULL,PRIMARY KEY(request_id,env_id));
CREATE TABLE IF NOT EXISTS workload_trusts(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,identity_id TEXT NOT NULL,env_id TEXT NOT NULL,issuer TEXT NOT NULL,audience TEXT NOT NULL,subject TEXT NOT NULL,jwks TEXT NOT NULL,scopes TEXT NOT NULL,ttl BIGINT NOT NULL,bound_claims TEXT NOT NULL,revoked BIGINT DEFAULT 0,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS workload_replay(key TEXT PRIMARY KEY,expires_at BIGINT NOT NULL);
ALTER TABLE tokens ADD COLUMN trust_id TEXT DEFAULT '';
CREATE TABLE IF NOT EXISTS transit_keys(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,name TEXT NOT NULL,current_version BIGINT NOT NULL,UNIQUE(org_id,name));
CREATE TABLE IF NOT EXISTS transit_versions(key_id TEXT NOT NULL,org_id TEXT NOT NULL,version BIGINT NOT NULL,key_enc TEXT NOT NULL,PRIMARY KEY(key_id,version));
ALTER TABLE orgs ADD COLUMN emergency_locked BIGINT NOT NULL DEFAULT 0;
ALTER TABLE apps ADD COLUMN emergency_locked BIGINT NOT NULL DEFAULT 0;
ALTER TABLE envs ADD COLUMN max_versions BIGINT DEFAULT 0;
ALTER TABLE leases ADD COLUMN attempted_at BIGINT DEFAULT 0;
ALTER TABLE audit ADD COLUMN seq BIGINT DEFAULT 0;
ALTER TABLE audit ADD COLUMN prev_hash TEXT DEFAULT '';
ALTER TABLE audit ADD COLUMN hash TEXT DEFAULT '';
CREATE TABLE IF NOT EXISTS audit_heads(org_id TEXT PRIMARY KEY,seq BIGINT NOT NULL,hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS wrap_tokens(token_hash TEXT PRIMARY KEY,env_id TEXT NOT NULL,payload_enc TEXT NOT NULL,created_by TEXT DEFAULT '',created_at BIGINT NOT NULL,expires_at BIGINT NOT NULL,used BIGINT DEFAULT 0);
CREATE INDEX IF NOT EXISTS idx_audit_org_seq ON audit(org_id,seq);
CREATE INDEX IF NOT EXISTS idx_wrap_tokens_expiry ON wrap_tokens(expires_at);
CREATE TABLE IF NOT EXISTS workload_bindings(identity_id TEXT PRIMARY KEY,org_id TEXT NOT NULL,revision TEXT NOT NULL,issuer TEXT NOT NULL,jwks_url TEXT NOT NULL,audience TEXT NOT NULL,subject TEXT NOT NULL,max_ttl_secs BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS workload_assertions(digest TEXT PRIMARY KEY,expires_at BIGINT NOT NULL);
ALTER TABLE tokens ADD COLUMN workload_revision TEXT DEFAULT '';
CREATE TABLE IF NOT EXISTS path_policies(env_id TEXT NOT NULL,role TEXT NOT NULL,rules TEXT NOT NULL,PRIMARY KEY(env_id,role));
CREATE TABLE IF NOT EXISTS compat_transit_keys(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,name TEXT NOT NULL,wrapping_key TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS idx_compat_transit_keys_name ON compat_transit_keys(org_id,name);
CREATE TABLE IF NOT EXISTS compat_transit_versions(key_id TEXT NOT NULL,version BIGINT NOT NULL,key_enc TEXT NOT NULL,created_at BIGINT NOT NULL,PRIMARY KEY(key_id,version));
ALTER TABLE rotation_schedules ADD COLUMN pending_enc TEXT DEFAULT '';
ALTER TABLE rotation_schedules ADD COLUMN static_target TEXT DEFAULT NULL;
ALTER TABLE rotation_schedules ADD COLUMN execution_token TEXT DEFAULT '';
CREATE UNIQUE INDEX IF NOT EXISTS idx_static_rotation_target ON rotation_schedules(static_target);
CREATE TABLE IF NOT EXISTS pki_devices(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,ca_id TEXT NOT NULL,app_id TEXT DEFAULT '',env_id TEXT DEFAULT '',name TEXT NOT NULL,model TEXT DEFAULT '',hardware_serial TEXT DEFAULT '',tags TEXT DEFAULT '',sans TEXT DEFAULT '',cert_days BIGINT DEFAULT 90,active_cert_id TEXT DEFAULT '',enroll_epoch BIGINT DEFAULT 0,deleting BIGINT DEFAULT 0,created_at BIGINT NOT NULL,updated_at BIGINT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS idx_pki_devices_ca_name ON pki_devices(ca_id,name);
CREATE INDEX IF NOT EXISTS idx_pki_devices_org ON pki_devices(org_id);
CREATE INDEX IF NOT EXISTS idx_pki_devices_env ON pki_devices(env_id);
CREATE TABLE IF NOT EXISTS pki_enrollments(id TEXT PRIMARY KEY,device_id TEXT NOT NULL,token_hash TEXT NOT NULL,expires_at BIGINT NOT NULL,used_at BIGINT DEFAULT 0,created_by TEXT DEFAULT '',created_at BIGINT NOT NULL,enroll_epoch BIGINT DEFAULT 0);
CREATE UNIQUE INDEX IF NOT EXISTS idx_pki_enrollments_hash ON pki_enrollments(token_hash);
CREATE INDEX IF NOT EXISTS idx_pki_enrollments_device ON pki_enrollments(device_id);
ALTER TABLE pki_certs ADD COLUMN device_id TEXT DEFAULT '';
ALTER TABLE pki_certs ADD COLUMN revoked_at BIGINT DEFAULT 0;
ALTER TABLE pki_certs ADD COLUMN issued_via TEXT DEFAULT '';
ALTER TABLE pki_cas ADD COLUMN parent_id TEXT DEFAULT '';
ALTER TABLE pki_cas ADD COLUMN revoked BIGINT DEFAULT 0;
ALTER TABLE pki_cas ADD COLUMN revoked_at BIGINT DEFAULT 0;
ALTER TABLE pki_cas ADD COLUMN hook_url TEXT DEFAULT '';
ALTER TABLE pki_cas ADD COLUMN hook_secret_enc TEXT DEFAULT '';
ALTER TABLE pki_cas ADD COLUMN attest_issuer TEXT DEFAULT '';
ALTER TABLE pki_cas ADD COLUMN attest_key_pem TEXT DEFAULT '';
ALTER TABLE pki_cas ADD COLUMN attest_alg TEXT DEFAULT 'ES256';
ALTER TABLE pki_cas ADD COLUMN attest_required BIGINT DEFAULT 0;
CREATE TABLE IF NOT EXISTS pki_groups(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,ca_id TEXT NOT NULL,name TEXT NOT NULL,env_id TEXT DEFAULT '',sans TEXT DEFAULT '',cert_days BIGINT DEFAULT 90,tags TEXT DEFAULT '',created_at BIGINT NOT NULL,updated_at BIGINT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS idx_pki_groups_ca_name ON pki_groups(ca_id,name);
CREATE INDEX IF NOT EXISTS idx_pki_groups_org ON pki_groups(org_id);
ALTER TABLE pki_devices ADD COLUMN group_id TEXT DEFAULT '';
ALTER TABLE pki_devices ADD COLUMN attested BIGINT DEFAULT 0;
ALTER TABLE pki_devices ADD COLUMN attestation TEXT DEFAULT '';
ALTER TABLE pki_enrollments ADD COLUMN revoke_previous BIGINT DEFAULT 0;
ALTER TABLE pki_enrollments ADD COLUMN nonce TEXT DEFAULT '';
ALTER TABLE pki_cas ADD COLUMN ca_kind TEXT DEFAULT 'root';
UPDATE pki_cas SET ca_kind='intermediate' WHERE parent_id<>'';
UPDATE pki_cas SET kind='x509' WHERE kind='root' OR kind='intermediate';
CREATE TABLE IF NOT EXISTS pki_renew_challenges(id TEXT PRIMARY KEY,device_id TEXT NOT NULL,cert_id TEXT NOT NULL,csr TEXT NOT NULL,challenge TEXT NOT NULL,expires_at BIGINT NOT NULL,used_at BIGINT DEFAULT 0);
CREATE INDEX IF NOT EXISTS idx_pki_renew_expiry ON pki_renew_challenges(expires_at);
CREATE TABLE IF NOT EXISTS pki_expiry_deliveries(org_id TEXT NOT NULL,user_id TEXT NOT NULL,day BIGINT NOT NULL,status TEXT NOT NULL,PRIMARY KEY(org_id,user_id,day));
ALTER TABLE pki_devices ADD COLUMN tpm_ak_public TEXT DEFAULT '';
ALTER TABLE pki_devices ADD COLUMN tpm_pcr_digest TEXT DEFAULT '';
ALTER TABLE pki_cas ADD COLUMN attest_mode TEXT DEFAULT 'jwt';
-- The canonical bootstrap columns: main's old runner applied this exact set
-- outside the numbered history before installing indexes.
ALTER TABLE envs ADD COLUMN mode TEXT DEFAULT 'sse';
ALTER TABLE envs ADD COLUMN restricted BIGINT DEFAULT 0;
ALTER TABLE envs ADD COLUMN require_approval BIGINT DEFAULT 0;
ALTER TABLE secrets ADD COLUMN e2e BIGINT DEFAULT 0;
ALTER TABLE secrets ADD COLUMN deleted_at BIGINT DEFAULT 0;
ALTER TABLE users ADD COLUMN active BIGINT DEFAULT 1;
ALTER TABLE tokens ADD COLUMN kind TEXT DEFAULT 'human';
ALTER TABLE tokens ADD COLUMN expires_at BIGINT DEFAULT 0;
ALTER TABLE leases ADD COLUMN username TEXT DEFAULT '';
ALTER TABLE leases ADD COLUMN config_enc TEXT DEFAULT '';
ALTER TABLE oidc_states ADD COLUMN nonce TEXT DEFAULT '';
ALTER TABLE pki_cas ADD COLUMN serial TEXT DEFAULT '';
ALTER TABLE rotation_schedules ADD COLUMN path TEXT DEFAULT '/';
ALTER TABLE rotation_schedules ADD COLUMN config_enc TEXT DEFAULT '';
ALTER TABLE users ADD COLUMN email_verified BIGINT DEFAULT 1;
CREATE INDEX IF NOT EXISTS idx_pki_certs_device ON pki_certs(device_id);
CREATE INDEX IF NOT EXISTS idx_pki_certs_expiry ON pki_certs(expires_at);
-- The canonical startup index set: main's old runner installed these outside
-- the numbered history, so a database built only from its migrations lacks them.
CREATE INDEX IF NOT EXISTS idx_secrets_env ON secrets(env_id);
CREATE INDEX IF NOT EXISTS idx_secret_versions_secret ON secret_versions(secret_id);
CREATE INDEX IF NOT EXISTS idx_audit_org ON audit(org_id,created_at);
CREATE INDEX IF NOT EXISTS idx_audit_org_seq ON audit(org_id,seq);
CREATE INDEX IF NOT EXISTS idx_wrap_tokens_expiry ON wrap_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_tokens_hash ON tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_user ON oauth_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_env_members_user ON env_members(user_id);
CREATE INDEX IF NOT EXISTS idx_leases_env ON leases(env_id);
CREATE INDEX IF NOT EXISTS idx_sync_state_integration ON integration_sync_state(integration_id);
CREATE INDEX IF NOT EXISTS idx_team_env_grants_env ON team_env_grants(env_id);
CREATE INDEX IF NOT EXISTS idx_instance_leases_expiry ON instance_leases(expires_at);
CREATE INDEX IF NOT EXISTS idx_rotations_due ON rotation_schedules(enabled,next_run);
CREATE INDEX IF NOT EXISTS idx_invites_email ON invites(email);
CREATE INDEX IF NOT EXISTS idx_auth_tokens_user ON auth_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_live_events_id ON live_events(id);
UPDATE envs SET restricted=1 WHERE id IN (SELECT env_id FROM env_members)
  AND NOT EXISTS (SELECT 1 FROM meta WHERE k='migration:env_restricted');
INSERT INTO meta(k,v) SELECT 'migration:env_restricted','0'
  WHERE NOT EXISTS (SELECT 1 FROM meta WHERE k='migration:env_restricted');
INSERT INTO meta(k,v) SELECT 'rotation_lifecycle','' WHERE NOT EXISTS (SELECT 1 FROM meta WHERE k='rotation_lifecycle');
