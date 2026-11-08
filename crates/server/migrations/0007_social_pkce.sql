-- Migration 7: social pkce.
-- Frozen history: applied to databases created before the runner tracked
-- checksums. Never edit this file; add a new numbered migration instead.
ALTER TABLE social_states ADD COLUMN nonce TEXT DEFAULT '';
ALTER TABLE social_states ADD COLUMN code_verifier TEXT DEFAULT '';
