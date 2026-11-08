ALTER TABLE orgs ADD COLUMN emergency_locked BIGINT NOT NULL DEFAULT 0;
ALTER TABLE apps ADD COLUMN emergency_locked BIGINT NOT NULL DEFAULT 0;
UPDATE envs SET restricted=1 WHERE id IN (SELECT env_id FROM env_members)
  AND NOT EXISTS (SELECT 1 FROM meta WHERE k='migration:env_restricted');
INSERT INTO meta(k,v) SELECT 'migration:env_restricted','0'
  WHERE NOT EXISTS (SELECT 1 FROM meta WHERE k='migration:env_restricted');
