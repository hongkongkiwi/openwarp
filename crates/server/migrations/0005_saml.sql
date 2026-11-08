-- Migration 5: saml.
-- Frozen history: applied to databases created before the runner tracked
-- checksums. Never edit this file; add a new numbered migration instead.
CREATE TABLE IF NOT EXISTS saml_configs(org_id TEXT PRIMARY KEY,idp_entity_id TEXT NOT NULL,idp_metadata_xml TEXT NOT NULL,sp_key_enc TEXT NOT NULL,sp_cert_pem TEXT NOT NULL,allow_unsigned_metadata BIGINT DEFAULT 0,metadata_trusted_cert TEXT DEFAULT '',auto_provision BIGINT DEFAULT 0,allowed_domains TEXT DEFAULT '',created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS saml_pending(state TEXT PRIMARY KEY,org_id TEXT NOT NULL,snapshot TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS saml_replay(key TEXT PRIMARY KEY,expires_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS saml_subjects(org_id TEXT NOT NULL,idp_entity_id TEXT NOT NULL,name_id TEXT NOT NULL,user_id TEXT NOT NULL,created_at BIGINT NOT NULL,PRIMARY KEY(org_id,idp_entity_id,name_id));
