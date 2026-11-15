ALTER TABLE envs ADD COLUMN key_generation BIGINT NOT NULL DEFAULT 1;
ALTER TABLE envs ADD COLUMN membership_version BIGINT NOT NULL DEFAULT 0;
ALTER TABLE envs ADD COLUMN rekey_pending INTEGER NOT NULL DEFAULT 0;
ALTER TABLE envs ADD COLUMN runner_rekey_authorized INTEGER NOT NULL DEFAULT 0;
UPDATE envs SET rekey_pending=1 WHERE EXISTS (SELECT 1 FROM meta WHERE SUBSTR(meta.k,1,15)='rekey_required:' AND SUBSTR(meta.k,16)=envs.id AND meta.v='1');
