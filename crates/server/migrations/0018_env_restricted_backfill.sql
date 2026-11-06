-- Environments that existed when the allowlist was introduced keep it.
-- Guarded by the meta sentinel so an intentional later change survives.
UPDATE envs SET restricted=1 WHERE id IN (SELECT env_id FROM env_members)
  AND NOT EXISTS (SELECT 1 FROM meta WHERE k='migration:env_restricted');
INSERT INTO meta(k,v) SELECT 'migration:env_restricted','0'
  WHERE NOT EXISTS (SELECT 1 FROM meta WHERE k='migration:env_restricted');
