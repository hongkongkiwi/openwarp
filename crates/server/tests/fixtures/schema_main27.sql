-- Derived independently from d39138e SCHEMA, bootstrap ALTERs, INDEXES and MIGRATIONS 2..27.
-- Only statements successfully executed by canonical SQLite startup are retained.
-- Synthetic applied_at and bootstrap timestamps are deterministic fixture values.
CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,email TEXT UNIQUE NOT NULL,pass_hash TEXT NOT NULL,pubkey TEXT NOT NULL,wrapped_privkey TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS oidc_subjects(issuer TEXT NOT NULL,subject TEXT NOT NULL,user_id TEXT NOT NULL,created_at BIGINT NOT NULL,PRIMARY KEY(issuer,subject));
CREATE TABLE IF NOT EXISTS orgs(id TEXT PRIMARY KEY,name TEXT NOT NULL,ip_allowlist TEXT DEFAULT '',created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS org_members(org_id TEXT NOT NULL,user_id TEXT NOT NULL,role TEXT NOT NULL,PRIMARY KEY(org_id,user_id));
CREATE TABLE IF NOT EXISTS teams(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,name TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS team_members(team_id TEXT NOT NULL,user_id TEXT NOT NULL,PRIMARY KEY(team_id,user_id));
CREATE TABLE IF NOT EXISTS apps(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,name TEXT NOT NULL,readme TEXT DEFAULT '',sse BIGINT DEFAULT 1,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS app_members(app_id TEXT NOT NULL,user_id TEXT NOT NULL,role TEXT NOT NULL,PRIMARY KEY(app_id,user_id));
CREATE TABLE IF NOT EXISTS envs(id TEXT PRIMARY KEY,app_id TEXT NOT NULL,name TEXT NOT NULL,env_key_wrapped TEXT NOT NULL,restricted BIGINT DEFAULT 0,require_approval BIGINT DEFAULT 0,max_versions BIGINT DEFAULT 0,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS env_members(env_id TEXT NOT NULL,user_id TEXT NOT NULL,PRIMARY KEY(env_id,user_id));
CREATE TABLE IF NOT EXISTS secrets(id TEXT PRIMARY KEY,env_id TEXT NOT NULL,path TEXT DEFAULT '/',key_enc TEXT NOT NULL,key_hash TEXT NOT NULL,value_enc TEXT NOT NULL,comment_enc TEXT DEFAULT '',tags TEXT DEFAULT '',secret_type TEXT DEFAULT 'secret',version BIGINT DEFAULT 1,deleted BIGINT DEFAULT 0,deleted_at BIGINT DEFAULT 0,updated_at BIGINT NOT NULL,updated_by TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS secret_versions(id TEXT PRIMARY KEY,secret_id TEXT NOT NULL,version BIGINT NOT NULL,key_enc TEXT NOT NULL,value_enc TEXT NOT NULL,comment_enc TEXT DEFAULT '',secret_type TEXT DEFAULT 'secret',path TEXT DEFAULT '/',tags TEXT DEFAULT '',created_at BIGINT NOT NULL,created_by TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS overrides(secret_id TEXT NOT NULL,user_id TEXT NOT NULL,value_enc TEXT NOT NULL,PRIMARY KEY(secret_id,user_id));
CREATE TABLE IF NOT EXISTS audit(id TEXT PRIMARY KEY,org_id TEXT DEFAULT '',app_id TEXT DEFAULT '',env_id TEXT DEFAULT '',actor TEXT DEFAULT '',action TEXT NOT NULL,detail TEXT DEFAULT '',created_at BIGINT NOT NULL,seq BIGINT DEFAULT 0,prev_hash TEXT DEFAULT '',hash TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS audit_heads(org_id TEXT PRIMARY KEY,seq BIGINT NOT NULL,hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tokens(id TEXT PRIMARY KEY,org_id TEXT DEFAULT '',app_id TEXT DEFAULT '',env_id TEXT DEFAULT '',name TEXT NOT NULL,token_hash TEXT NOT NULL,role TEXT DEFAULT 'developer',expires_at BIGINT DEFAULT 0,scopes TEXT DEFAULT '',last_used_at BIGINT DEFAULT 0,created_at BIGINT NOT NULL,created_by TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS integrations(id TEXT PRIMARY KEY,env_id TEXT NOT NULL,kind TEXT NOT NULL,name TEXT NOT NULL,config_enc TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS lockbox(id TEXT PRIMARY KEY,value_enc TEXT NOT NULL,expires_at BIGINT NOT NULL,max_views BIGINT DEFAULT 1,views BIGINT DEFAULT 0,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS wrap_tokens(token_hash TEXT PRIMARY KEY,env_id TEXT NOT NULL,payload_enc TEXT NOT NULL,created_by TEXT DEFAULT '',created_at BIGINT NOT NULL,expires_at BIGINT NOT NULL,used BIGINT DEFAULT 0);
CREATE TABLE IF NOT EXISTS leases(id TEXT PRIMARY KEY,env_id TEXT NOT NULL,name TEXT NOT NULL,value_enc TEXT NOT NULL,expires_at BIGINT NOT NULL,revoked BIGINT DEFAULT 0,attempted_at BIGINT DEFAULT 0,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY,v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS env_keys(env_id TEXT NOT NULL,user_id TEXT NOT NULL,wrapped_key TEXT NOT NULL,PRIMARY KEY(env_id,user_id));
CREATE TABLE IF NOT EXISTS oidc_states(state TEXT PRIMARY KEY,org_id TEXT NOT NULL,nonce TEXT DEFAULT '',created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS identities(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,name TEXT NOT NULL,role TEXT DEFAULT 'developer',created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS identity_credentials(id TEXT PRIMARY KEY,identity_id TEXT NOT NULL,client_id TEXT UNIQUE NOT NULL,secret_hash TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS proposals(id TEXT PRIMARY KEY,env_id TEXT NOT NULL,author TEXT NOT NULL,status TEXT DEFAULT 'pending',payload_enc TEXT NOT NULL,created_at BIGINT NOT NULL,decided_by TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS access_requests(id TEXT PRIMARY KEY,env_id TEXT NOT NULL,user_id TEXT NOT NULL,reason TEXT DEFAULT '',status TEXT DEFAULT 'pending',created_at BIGINT NOT NULL,decided_by TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS pki_cas(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,name TEXT NOT NULL,cert_pem TEXT NOT NULL,key_enc TEXT NOT NULL,serial TEXT DEFAULT '',created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS integration_sync_state(integration_id TEXT NOT NULL,remote_name TEXT NOT NULL,value_hash TEXT NOT NULL,PRIMARY KEY(integration_id,remote_name));
CREATE TABLE IF NOT EXISTS oauth_clients(client_id TEXT PRIMARY KEY,client_secret_hash TEXT DEFAULT '',name TEXT DEFAULT '',redirect_uris TEXT DEFAULT '[]',scopes TEXT DEFAULT '',created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS oauth_codes(code_hash TEXT PRIMARY KEY,client_id TEXT NOT NULL,user_id TEXT NOT NULL,redirect_uri TEXT NOT NULL,code_challenge TEXT NOT NULL,scope TEXT DEFAULT '',resource TEXT DEFAULT '',expires_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS oauth_tokens(token_hash TEXT PRIMARY KEY,client_id TEXT NOT NULL,user_id TEXT NOT NULL,scope TEXT DEFAULT '',resource TEXT DEFAULT '',kind TEXT DEFAULT 'access',pair_id TEXT DEFAULT '',expires_at BIGINT NOT NULL,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS roles(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,name TEXT NOT NULL,permissions TEXT DEFAULT '[]');
CREATE TABLE IF NOT EXISTS log_streams(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,name TEXT NOT NULL,url TEXT NOT NULL,secret TEXT DEFAULT '',created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS log_deliveries(id TEXT PRIMARY KEY,stream_id TEXT NOT NULL,event TEXT NOT NULL,payload TEXT DEFAULT '',status TEXT DEFAULT 'pending',attempts BIGINT DEFAULT 0,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS rotation_schedules(id TEXT PRIMARY KEY,env_id TEXT NOT NULL,key_name TEXT NOT NULL,path TEXT DEFAULT '/',interval_secs BIGINT NOT NULL,next_run BIGINT NOT NULL,enabled BIGINT DEFAULT 1,config_enc TEXT DEFAULT '',created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS mfa_challenges(token TEXT PRIMARY KEY,user_id TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS pki_certs(id TEXT PRIMARY KEY,ca_id TEXT NOT NULL,cn TEXT NOT NULL,cert_pem TEXT NOT NULL,serial TEXT NOT NULL,revoked BIGINT DEFAULT 0,expires_at BIGINT NOT NULL,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS rate_limits(key TEXT PRIMARY KEY,window_start BIGINT NOT NULL,count BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS social_states(state TEXT PRIMARY KEY,provider TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS social_subjects(provider TEXT NOT NULL,subject TEXT NOT NULL,user_id TEXT NOT NULL,created_at BIGINT NOT NULL,PRIMARY KEY(provider,subject));
CREATE TABLE IF NOT EXISTS invites(token_hash TEXT PRIMARY KEY,email TEXT NOT NULL,org_id TEXT NOT NULL,role TEXT NOT NULL,created_at BIGINT NOT NULL,expires_at BIGINT NOT NULL,accepted BIGINT DEFAULT 0);
CREATE TABLE IF NOT EXISTS auth_tokens(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL,kind TEXT NOT NULL,created_at BIGINT NOT NULL,expires_at BIGINT NOT NULL,used BIGINT DEFAULT 0);
CREATE TABLE IF NOT EXISTS team_env_grants(team_id TEXT NOT NULL,env_id TEXT NOT NULL,PRIMARY KEY(team_id,env_id));
CREATE TABLE IF NOT EXISTS instance_leases(name TEXT PRIMARY KEY,owner TEXT NOT NULL,expires_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS schema_migrations(version BIGINT PRIMARY KEY,applied_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS saml_configs(org_id TEXT PRIMARY KEY,idp_entity_id TEXT NOT NULL,idp_metadata_xml TEXT NOT NULL,sp_key_enc TEXT NOT NULL,sp_cert_pem TEXT NOT NULL,allow_unsigned_metadata BIGINT DEFAULT 0,metadata_trusted_cert TEXT DEFAULT '',auto_provision BIGINT DEFAULT 0,allowed_domains TEXT DEFAULT '',created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS saml_pending(state TEXT PRIMARY KEY,org_id TEXT NOT NULL,snapshot TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS saml_replay(key TEXT PRIMARY KEY,expires_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS saml_subjects(org_id TEXT NOT NULL,idp_entity_id TEXT NOT NULL,name_id TEXT NOT NULL,user_id TEXT NOT NULL,created_at BIGINT NOT NULL,PRIMARY KEY(org_id,idp_entity_id,name_id));
CREATE TABLE IF NOT EXISTS rotation_hooks(org_id TEXT PRIMARY KEY,url TEXT NOT NULL,secret_enc TEXT DEFAULT '',created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS live_events(id BIGINT PRIMARY KEY,org_id TEXT NOT NULL,app_id TEXT DEFAULT '',env_id TEXT DEFAULT '',action TEXT NOT NULL,detail TEXT DEFAULT '',created_at BIGINT NOT NULL);
ALTER TABLE envs ADD COLUMN mode TEXT DEFAULT 'sse';
ALTER TABLE secrets ADD COLUMN e2e BIGINT DEFAULT 0;
ALTER TABLE users ADD COLUMN active BIGINT DEFAULT 1;
ALTER TABLE tokens ADD COLUMN kind TEXT DEFAULT 'human';
ALTER TABLE leases ADD COLUMN username TEXT DEFAULT '';
ALTER TABLE leases ADD COLUMN config_enc TEXT DEFAULT '';
ALTER TABLE users ADD COLUMN email_verified BIGINT DEFAULT 1;
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
INSERT INTO schema_migrations(version,applied_at) VALUES(1,101);
-- main migration 2
INSERT INTO schema_migrations(version,applied_at) VALUES(2,102);
-- main migration 3
CREATE TABLE IF NOT EXISTS team_env_grants(team_id TEXT NOT NULL,env_id TEXT NOT NULL,PRIMARY KEY(team_id,env_id));
INSERT INTO schema_migrations(version,applied_at) VALUES(3,103);
-- main migration 4
CREATE TABLE IF NOT EXISTS instance_leases(name TEXT PRIMARY KEY,owner TEXT NOT NULL,expires_at BIGINT NOT NULL);
INSERT INTO schema_migrations(version,applied_at) VALUES(4,104);
-- main migration 5
CREATE TABLE IF NOT EXISTS saml_configs(org_id TEXT PRIMARY KEY,idp_entity_id TEXT NOT NULL,idp_metadata_xml TEXT NOT NULL,sp_key_enc TEXT NOT NULL,sp_cert_pem TEXT NOT NULL,allow_unsigned_metadata BIGINT DEFAULT 0,metadata_trusted_cert TEXT DEFAULT '',auto_provision BIGINT DEFAULT 0,allowed_domains TEXT DEFAULT '',created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS saml_pending(state TEXT PRIMARY KEY,org_id TEXT NOT NULL,snapshot TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS saml_replay(key TEXT PRIMARY KEY,expires_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS saml_subjects(org_id TEXT NOT NULL,idp_entity_id TEXT NOT NULL,name_id TEXT NOT NULL,user_id TEXT NOT NULL,created_at BIGINT NOT NULL,PRIMARY KEY(org_id,idp_entity_id,name_id));
INSERT INTO schema_migrations(version,applied_at) VALUES(5,105);
-- main migration 6
CREATE TABLE IF NOT EXISTS rotation_hooks(org_id TEXT PRIMARY KEY,url TEXT NOT NULL,secret_enc TEXT DEFAULT '',created_at BIGINT NOT NULL);
INSERT INTO schema_migrations(version,applied_at) VALUES(6,106);
-- main migration 7
ALTER TABLE social_states ADD COLUMN nonce TEXT DEFAULT '';
ALTER TABLE social_states ADD COLUMN code_verifier TEXT DEFAULT '';
INSERT INTO schema_migrations(version,applied_at) VALUES(7,107);
-- main migration 8
CREATE TABLE IF NOT EXISTS live_events(id BIGINT PRIMARY KEY,org_id TEXT NOT NULL,app_id TEXT DEFAULT '',env_id TEXT DEFAULT '',action TEXT NOT NULL,detail TEXT DEFAULT '',created_at BIGINT NOT NULL);
INSERT INTO schema_migrations(version,applied_at) VALUES(8,108);
-- main migration 9
ALTER TABLE social_states ADD COLUMN link_user TEXT DEFAULT '';
ALTER TABLE oidc_states ADD COLUMN link_user TEXT DEFAULT '';
CREATE TABLE IF NOT EXISTS identity_bindings(issuer TEXT NOT NULL,subject TEXT NOT NULL,user_id TEXT NOT NULL,provider TEXT DEFAULT '',created_at BIGINT NOT NULL,PRIMARY KEY(issuer,subject));
CREATE TABLE IF NOT EXISTS logout_replay(jti TEXT PRIMARY KEY,expires_at BIGINT NOT NULL);
INSERT INTO schema_migrations(version,applied_at) VALUES(9,109);
-- main migration 10
CREATE TABLE IF NOT EXISTS ldap_configs(org_id TEXT PRIMARY KEY,url TEXT NOT NULL DEFAULT '',bind_dn TEXT NOT NULL DEFAULT '',bind_password_enc TEXT NOT NULL DEFAULT '',base_dn TEXT NOT NULL DEFAULT '',user_filter TEXT NOT NULL DEFAULT '(uid={username})',email_attr TEXT NOT NULL DEFAULT 'mail',name_attr TEXT NOT NULL DEFAULT 'displayName',group_attr TEXT NOT NULL DEFAULT 'memberOf',group_roles TEXT NOT NULL DEFAULT '',default_role TEXT NOT NULL DEFAULT 'developer',auto_provision BIGINT NOT NULL DEFAULT 0,allowed_domains TEXT NOT NULL DEFAULT '',ca_cert_pem TEXT NOT NULL DEFAULT '',updated_at BIGINT NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS ldap_subjects(org_id TEXT NOT NULL,dn TEXT NOT NULL,user_id TEXT NOT NULL,created_at BIGINT NOT NULL,role TEXT NOT NULL DEFAULT '',PRIMARY KEY(org_id,dn));
INSERT INTO schema_migrations(version,applied_at) VALUES(10,110);
-- main migration 11
INSERT INTO schema_migrations(version,applied_at) VALUES(11,111);
-- main migration 12
ALTER TABLE orgs ADD COLUMN reuse_check BIGINT DEFAULT 1;
ALTER TABLE apps ADD COLUMN reuse_check BIGINT DEFAULT 1;
ALTER TABLE secrets ADD COLUMN value_fp TEXT DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_secrets_fp ON secrets(value_fp);
INSERT INTO schema_migrations(version,applied_at) VALUES(12,112);
-- main migration 13
INSERT INTO schema_migrations(version,applied_at) VALUES(13,113);
-- main migration 14
ALTER TABLE pki_cas ADD COLUMN kind TEXT DEFAULT 'x509';
ALTER TABLE pki_cas ADD COLUMN allow_forwarding BIGINT DEFAULT 0;
CREATE TABLE IF NOT EXISTS ssh_principal_grants(ca_id TEXT NOT NULL,role TEXT NOT NULL,principals TEXT NOT NULL,max_ttl BIGINT DEFAULT 900,PRIMARY KEY(ca_id,role));
CREATE TABLE IF NOT EXISTS ssh_certs(id TEXT PRIMARY KEY,ca_id TEXT NOT NULL,key_id TEXT NOT NULL,principal TEXT NOT NULL,public_key TEXT NOT NULL,cert TEXT NOT NULL,serial BIGINT NOT NULL,actor TEXT NOT NULL,revoked BIGINT DEFAULT 0,valid_after BIGINT NOT NULL,valid_before BIGINT NOT NULL,created_at BIGINT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_ssh_certs_ca ON ssh_certs(ca_id,created_at);
CREATE INDEX IF NOT EXISTS idx_ssh_grants_ca ON ssh_principal_grants(ca_id);
INSERT INTO schema_migrations(version,applied_at) VALUES(14,114);
-- main migration 15
ALTER TABLE ssh_certs ADD COLUMN cert_type TEXT DEFAULT 'user';
CREATE TABLE IF NOT EXISTS ssh_hosts(id TEXT PRIMARY KEY,ca_id TEXT NOT NULL,hostname TEXT NOT NULL,public_key TEXT NOT NULL,fingerprint TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ssh_hosts_key ON ssh_hosts(ca_id,hostname,fingerprint);
CREATE TABLE IF NOT EXISTS step_up_challenges(challenge_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL,risk TEXT NOT NULL,need_totp BIGINT DEFAULT 0,need_email BIGINT DEFAULT 0,email_code_hash TEXT DEFAULT '',attempts BIGINT DEFAULT 0,created_at BIGINT NOT NULL,expires_at BIGINT NOT NULL,used BIGINT DEFAULT 0);
CREATE TABLE IF NOT EXISTS step_up_grants(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL,risk TEXT NOT NULL,created_at BIGINT NOT NULL,expires_at BIGINT NOT NULL,used BIGINT DEFAULT 0);
INSERT INTO schema_migrations(version,applied_at) VALUES(15,115);
-- main migration 16
ALTER TABLE envs ADD COLUMN runner_id TEXT DEFAULT '';
ALTER TABLE secrets ADD COLUMN path_enc TEXT DEFAULT '';
ALTER TABLE secrets ADD COLUMN tags_enc TEXT DEFAULT '';
ALTER TABLE secrets ADD COLUMN key_index TEXT DEFAULT '';
ALTER TABLE users ADD COLUMN auth_version BIGINT DEFAULT 1;
ALTER TABLE users ADD COLUMN kdf_salt TEXT DEFAULT '';
ALTER TABLE users ADD COLUMN kdf_iterations BIGINT DEFAULT 0;
ALTER TABLE users ADD COLUMN kdf_algo TEXT DEFAULT '';
ALTER TABLE users ADD COLUMN auth_key_enc TEXT DEFAULT '';
CREATE TABLE IF NOT EXISTS passkeys(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,name TEXT DEFAULT '',credential_id TEXT NOT NULL,credential_json TEXT NOT NULL,sign_count BIGINT DEFAULT 0,created_at BIGINT NOT NULL,last_used_at BIGINT DEFAULT 0);
CREATE TABLE IF NOT EXISTS passkey_registrations(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,state_json TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS mfa_passkey_states(mfa_token TEXT PRIMARY KEY,user_id TEXT NOT NULL,state_json TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS email_codes(user_id TEXT NOT NULL,purpose TEXT NOT NULL,code_hash TEXT NOT NULL,created_at BIGINT NOT NULL,expires_at BIGINT NOT NULL,attempts BIGINT DEFAULT 0,PRIMARY KEY(user_id,purpose));
CREATE TABLE IF NOT EXISTS runners(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,name TEXT NOT NULL,pubkey TEXT NOT NULL,token_hash TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS runner_env_keys(runner_id TEXT NOT NULL,env_id TEXT NOT NULL,wrapped_key TEXT NOT NULL,PRIMARY KEY(runner_id,env_id));
CREATE TABLE IF NOT EXISTS sync_jobs(id TEXT PRIMARY KEY,env_id TEXT NOT NULL,integration_id TEXT NOT NULL,runner_id TEXT NOT NULL,kind TEXT DEFAULT 'sync',status TEXT DEFAULT 'pending',detail TEXT DEFAULT '',created_at BIGINT NOT NULL,claimed_at BIGINT DEFAULT 0,claim_id TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS auth_challenges(id_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL,challenge TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_secrets_key_index ON secrets(env_id,key_index);
CREATE INDEX IF NOT EXISTS idx_passkeys_user ON passkeys(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_passkeys_credential ON passkeys(credential_id);
CREATE INDEX IF NOT EXISTS idx_runners_token ON runners(token_hash);
CREATE INDEX IF NOT EXISTS idx_sync_jobs_pending ON sync_jobs(status,created_at);
CREATE INDEX IF NOT EXISTS idx_sync_jobs_integration ON sync_jobs(integration_id,status);
CREATE INDEX IF NOT EXISTS idx_auth_challenges_user ON auth_challenges(user_id);
INSERT INTO schema_migrations(version,applied_at) VALUES(16,116);
-- main migration 17
CREATE TABLE IF NOT EXISTS audit_heads(org_id TEXT PRIMARY KEY,seq BIGINT NOT NULL,hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS wrap_tokens(token_hash TEXT PRIMARY KEY,env_id TEXT NOT NULL,payload_enc TEXT NOT NULL,created_by TEXT DEFAULT '',created_at BIGINT NOT NULL,expires_at BIGINT NOT NULL,used BIGINT DEFAULT 0);
CREATE INDEX IF NOT EXISTS idx_audit_org_seq ON audit(org_id,seq);
CREATE INDEX IF NOT EXISTS idx_wrap_tokens_expiry ON wrap_tokens(expires_at);
INSERT INTO schema_migrations(version,applied_at) VALUES(17,117);
-- main migration 18
ALTER TABLE orgs ADD COLUMN emergency_locked BIGINT NOT NULL DEFAULT 0;
ALTER TABLE apps ADD COLUMN emergency_locked BIGINT NOT NULL DEFAULT 0;
INSERT INTO schema_migrations(version,applied_at) VALUES(18,118);
-- main migration 19
CREATE TABLE IF NOT EXISTS change_requests(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,title TEXT NOT NULL,author TEXT NOT NULL,revision BIGINT NOT NULL,status TEXT NOT NULL,approved_by TEXT DEFAULT '',created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS change_request_envs(request_id TEXT NOT NULL,env_id TEXT NOT NULL,payload_enc TEXT NOT NULL,PRIMARY KEY(request_id,env_id));
INSERT INTO schema_migrations(version,applied_at) VALUES(19,119);
-- main migration 20
CREATE TABLE IF NOT EXISTS workload_trusts(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,identity_id TEXT NOT NULL,env_id TEXT NOT NULL,issuer TEXT NOT NULL,audience TEXT NOT NULL,subject TEXT NOT NULL,jwks TEXT NOT NULL,scopes TEXT NOT NULL,ttl BIGINT NOT NULL,bound_claims TEXT NOT NULL,revoked BIGINT DEFAULT 0,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS workload_replay(key TEXT PRIMARY KEY,expires_at BIGINT NOT NULL);
ALTER TABLE tokens ADD COLUMN trust_id TEXT DEFAULT '';
INSERT INTO schema_migrations(version,applied_at) VALUES(20,120);
-- main migration 21
CREATE TABLE IF NOT EXISTS transit_keys(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,name TEXT NOT NULL,current_version BIGINT NOT NULL,UNIQUE(org_id,name));
CREATE TABLE IF NOT EXISTS transit_versions(key_id TEXT NOT NULL,org_id TEXT NOT NULL,version BIGINT NOT NULL,key_enc TEXT NOT NULL,PRIMARY KEY(key_id,version));
INSERT INTO schema_migrations(version,applied_at) VALUES(21,121);
-- main migration 22
CREATE TABLE workload_bindings(identity_id TEXT PRIMARY KEY,org_id TEXT NOT NULL,revision TEXT NOT NULL,issuer TEXT NOT NULL,jwks_url TEXT NOT NULL,audience TEXT NOT NULL,subject TEXT NOT NULL,max_ttl_secs BIGINT NOT NULL);
CREATE TABLE workload_assertions(digest TEXT PRIMARY KEY,expires_at BIGINT NOT NULL);
ALTER TABLE tokens ADD COLUMN workload_revision TEXT DEFAULT '';
CREATE TABLE path_policies(env_id TEXT NOT NULL,role TEXT NOT NULL,rules TEXT NOT NULL,PRIMARY KEY(env_id,role));
CREATE TABLE compat_transit_keys(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,name TEXT NOT NULL,wrapping_key TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE UNIQUE INDEX idx_compat_transit_keys_name ON compat_transit_keys(org_id,name);
CREATE TABLE compat_transit_versions(key_id TEXT NOT NULL,version BIGINT NOT NULL,key_enc TEXT NOT NULL,created_at BIGINT NOT NULL,PRIMARY KEY(key_id,version));
ALTER TABLE rotation_schedules ADD COLUMN pending_enc TEXT DEFAULT '';
ALTER TABLE rotation_schedules ADD COLUMN static_target TEXT DEFAULT NULL;
ALTER TABLE rotation_schedules ADD COLUMN execution_token TEXT DEFAULT '';
CREATE UNIQUE INDEX idx_static_rotation_target ON rotation_schedules(static_target);
INSERT INTO schema_migrations(version,applied_at) VALUES(22,122);
-- main migration 23
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
INSERT INTO schema_migrations(version,applied_at) VALUES(23,123);
-- main migration 24
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
INSERT INTO schema_migrations(version,applied_at) VALUES(24,124);
-- main migration 25
CREATE TABLE IF NOT EXISTS pki_renew_challenges(id TEXT PRIMARY KEY,device_id TEXT NOT NULL,cert_id TEXT NOT NULL,csr TEXT NOT NULL,challenge TEXT NOT NULL,expires_at BIGINT NOT NULL,used_at BIGINT DEFAULT 0);
CREATE INDEX IF NOT EXISTS idx_pki_renew_expiry ON pki_renew_challenges(expires_at);
CREATE TABLE IF NOT EXISTS pki_expiry_deliveries(org_id TEXT NOT NULL,user_id TEXT NOT NULL,day BIGINT NOT NULL,status TEXT NOT NULL,PRIMARY KEY(org_id,user_id,day));
ALTER TABLE pki_devices ADD COLUMN tpm_ak_public TEXT DEFAULT '';
ALTER TABLE pki_devices ADD COLUMN tpm_pcr_digest TEXT DEFAULT '';
ALTER TABLE pki_cas ADD COLUMN attest_mode TEXT DEFAULT 'jwt';
INSERT INTO schema_migrations(version,applied_at) VALUES(25,125);
-- main migration 26
CREATE TABLE IF NOT EXISTS change_requests(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,title TEXT NOT NULL,author TEXT NOT NULL,revision BIGINT NOT NULL,status TEXT NOT NULL,approved_by TEXT DEFAULT '',created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS change_request_envs(request_id TEXT NOT NULL,env_id TEXT NOT NULL,payload_enc TEXT NOT NULL,PRIMARY KEY(request_id,env_id));
CREATE TABLE IF NOT EXISTS workload_trusts(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,identity_id TEXT NOT NULL,env_id TEXT NOT NULL,issuer TEXT NOT NULL,audience TEXT NOT NULL,subject TEXT NOT NULL,jwks TEXT NOT NULL,scopes TEXT NOT NULL,ttl BIGINT NOT NULL,bound_claims TEXT NOT NULL,revoked BIGINT DEFAULT 0,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS workload_replay(key TEXT PRIMARY KEY,expires_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS transit_keys(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,name TEXT NOT NULL,current_version BIGINT NOT NULL,UNIQUE(org_id,name));
CREATE TABLE IF NOT EXISTS transit_versions(key_id TEXT NOT NULL,org_id TEXT NOT NULL,version BIGINT NOT NULL,key_enc TEXT NOT NULL,PRIMARY KEY(key_id,version));
CREATE TABLE IF NOT EXISTS audit_heads(org_id TEXT PRIMARY KEY,seq BIGINT NOT NULL,hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS wrap_tokens(token_hash TEXT PRIMARY KEY,env_id TEXT NOT NULL,payload_enc TEXT NOT NULL,created_by TEXT DEFAULT '',created_at BIGINT NOT NULL,expires_at BIGINT NOT NULL,used BIGINT DEFAULT 0);
CREATE INDEX IF NOT EXISTS idx_audit_org_seq ON audit(org_id,seq);
CREATE INDEX IF NOT EXISTS idx_wrap_tokens_expiry ON wrap_tokens(expires_at);
CREATE TABLE IF NOT EXISTS pki_devices(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,ca_id TEXT NOT NULL,app_id TEXT DEFAULT '',env_id TEXT DEFAULT '',name TEXT NOT NULL,model TEXT DEFAULT '',hardware_serial TEXT DEFAULT '',tags TEXT DEFAULT '',sans TEXT DEFAULT '',cert_days BIGINT DEFAULT 90,active_cert_id TEXT DEFAULT '',enroll_epoch BIGINT DEFAULT 0,deleting BIGINT DEFAULT 0,created_at BIGINT NOT NULL,updated_at BIGINT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS idx_pki_devices_ca_name ON pki_devices(ca_id,name);
CREATE INDEX IF NOT EXISTS idx_pki_devices_org ON pki_devices(org_id);
CREATE INDEX IF NOT EXISTS idx_pki_devices_env ON pki_devices(env_id);
CREATE TABLE IF NOT EXISTS pki_enrollments(id TEXT PRIMARY KEY,device_id TEXT NOT NULL,token_hash TEXT NOT NULL,expires_at BIGINT NOT NULL,used_at BIGINT DEFAULT 0,created_by TEXT DEFAULT '',created_at BIGINT NOT NULL,enroll_epoch BIGINT DEFAULT 0);
CREATE UNIQUE INDEX IF NOT EXISTS idx_pki_enrollments_hash ON pki_enrollments(token_hash);
CREATE INDEX IF NOT EXISTS idx_pki_enrollments_device ON pki_enrollments(device_id);
CREATE TABLE IF NOT EXISTS pki_groups(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,ca_id TEXT NOT NULL,name TEXT NOT NULL,env_id TEXT DEFAULT '',sans TEXT DEFAULT '',cert_days BIGINT DEFAULT 90,tags TEXT DEFAULT '',created_at BIGINT NOT NULL,updated_at BIGINT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS idx_pki_groups_ca_name ON pki_groups(ca_id,name);
CREATE INDEX IF NOT EXISTS idx_pki_groups_org ON pki_groups(org_id);
UPDATE pki_cas SET ca_kind='intermediate' WHERE parent_id<>'';
UPDATE pki_cas SET kind='x509' WHERE kind='root' OR kind='intermediate';
CREATE TABLE IF NOT EXISTS pki_renew_challenges(id TEXT PRIMARY KEY,device_id TEXT NOT NULL,cert_id TEXT NOT NULL,csr TEXT NOT NULL,challenge TEXT NOT NULL,expires_at BIGINT NOT NULL,used_at BIGINT DEFAULT 0);
CREATE INDEX IF NOT EXISTS idx_pki_renew_expiry ON pki_renew_challenges(expires_at);
CREATE TABLE IF NOT EXISTS pki_expiry_deliveries(org_id TEXT NOT NULL,user_id TEXT NOT NULL,day BIGINT NOT NULL,status TEXT NOT NULL,PRIMARY KEY(org_id,user_id,day));
INSERT INTO schema_migrations(version,applied_at) VALUES(26,126);
-- main migration 27
CREATE INDEX IF NOT EXISTS idx_pki_certs_device ON pki_certs(device_id);
CREATE INDEX IF NOT EXISTS idx_pki_certs_expiry ON pki_certs(expires_at);
INSERT INTO schema_migrations(version,applied_at) VALUES(27,127);
-- canonical bootstrap meta
INSERT INTO meta(k,v) SELECT 'rotation_lifecycle','' WHERE NOT EXISTS (SELECT 1 FROM meta WHERE k='rotation_lifecycle');
UPDATE envs SET restricted=1 WHERE id IN (SELECT env_id FROM env_members);
INSERT INTO meta(k,v) VALUES('migration:env_restricted','127');
