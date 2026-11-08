-- Migration 10: ldap.
-- Frozen history: applied to databases created before the runner tracked
-- checksums. Never edit this file; add a new numbered migration instead.
CREATE TABLE IF NOT EXISTS ldap_configs(org_id TEXT PRIMARY KEY,url TEXT NOT NULL DEFAULT '',bind_dn TEXT NOT NULL DEFAULT '',bind_password_enc TEXT NOT NULL DEFAULT '',base_dn TEXT NOT NULL DEFAULT '',user_filter TEXT NOT NULL DEFAULT '(uid={username})',email_attr TEXT NOT NULL DEFAULT 'mail',name_attr TEXT NOT NULL DEFAULT 'displayName',group_attr TEXT NOT NULL DEFAULT 'memberOf',group_roles TEXT NOT NULL DEFAULT '',default_role TEXT NOT NULL DEFAULT 'developer',auto_provision BIGINT NOT NULL DEFAULT 0,allowed_domains TEXT NOT NULL DEFAULT '',ca_cert_pem TEXT NOT NULL DEFAULT '',updated_at BIGINT NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS ldap_subjects(org_id TEXT NOT NULL,dn TEXT NOT NULL,user_id TEXT NOT NULL,created_at BIGINT NOT NULL,role TEXT NOT NULL DEFAULT '',PRIMARY KEY(org_id,dn));
