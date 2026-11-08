-- Reconciles the main branch's shipped version 27: device lookup and expiry indexes.
CREATE INDEX IF NOT EXISTS idx_pki_certs_device ON pki_certs(device_id);
CREATE INDEX IF NOT EXISTS idx_pki_certs_expiry ON pki_certs(expires_at);
