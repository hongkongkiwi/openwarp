-- PR7 workspace policy and tracked invitations: management ids, the inviter of
-- record, and the instance-level creation policy rows the policy lock uses.
ALTER TABLE invites ADD COLUMN id TEXT;
ALTER TABLE invites ADD COLUMN invited_by TEXT DEFAULT '';
CREATE UNIQUE INDEX IF NOT EXISTS idx_invites_id ON invites(id);
INSERT INTO meta(k,v) SELECT 'workspace_policy_lock','1' WHERE NOT EXISTS (SELECT 1 FROM meta WHERE k='workspace_policy_lock');
INSERT INTO meta(k,v) SELECT 'workspace_creation_open','1' WHERE NOT EXISTS (SELECT 1 FROM meta WHERE k='workspace_creation_open');
