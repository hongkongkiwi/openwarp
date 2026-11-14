'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.join(__dirname, '../src');
const app = fs.readFileSync(path.join(root, 'app.rs'), 'utf8');
const catalog = {
  'app.rs': {
    major: ['delete_org', 'leave_org', 'update_member_role', 'set_member_lock', 'invite_member', 'delete_env', 'set_env_policy', 'remove_member', 'delete_app', 'clone_env', 'deploy_secrets', 'delete_secret', 'undelete_secret', 'destroy_secret', 'restore', 'set_override', 'delete_override', 'create_token', 'create_team', 'add_team_grant', 'remove_team_grant', 'add_team_member', 'remove_team_member', 'create_lockbox', 'create_integration', 'sync_integration', 'test_integration', 'update_integration', 'delete_integration', 'pitr', 'put_rotation_hook', 'delete_rotation_hook', 'rotate_secret', 'e2e_put', 'e2e_grant', 'e2e_rekey', 'e2e_revoke', 'unlink_identity', 'put_feature_grants', 'set_signups', 'create_identity', 'delete_identity', 'rotate_identity', 'decide_proposal', 'decide_access', 'create_lease_v2', 'revoke_lease', 'issue_cert', 'revoke_cert', 'revoke_device', 'delete_device', 'revoke_group', 'revoke_ca', 'revoke_token', 'create_role', 'create_stream', 'renew_lease', 'create_rotation', 'delete_rotation', 'put_ssh_grants', 'revoke_ssh_cert', 'add_ssh_host', 'delete_ssh_host', 'ssh_sign_host'],
    very: ['transfer_org', 'export_env', 'org_settings', 'put_saml_config', 'put_ldap_config', 'delete_ldap_config', 'set_instance_owner', 'rotate_master', 'create_ssh_ca'],
    conditional: ['create_ca', 'ssh_sign'],
  },
  'workspaces.rs': { major: ['revoke', 'resend'] },
  'path_policy.rs': { major: ['put', 'delete'] },
  'static_rotation.rs': { major: ['run'] },
  'workloads.rs': { major: ['manage'] },
  'workload.rs': { major: ['create', 'revoke'] },
  'change_requests.rs': { major: ['action'] },
  'ai.rs': { major: ['execute', 'delete_draft'] },
};
function functions(source, name) {
  const starts = [...source.matchAll(new RegExp('(?:pub(?:\\([^)]*\\))?\\s+)?async fn ' + name + '\\(', 'g'))];
  return starts.map(match => {
    const rest = source.slice(match.index);
    const end = rest.slice(1).search(/\n(?:pub(?:\([^)]*\))?\s+)?(?:async )?fn /);
    return end < 0 ? rest : rest.slice(0, end + 1);
  });
}
for (const [file, risks] of Object.entries(catalog)) {
  test(file + ' keeps the documented sensitive HTTP handlers guarded', () => {
    const source = fs.readFileSync(path.join(root, file), 'utf8');
    for (const [risk, names] of Object.entries(risks)) for (const name of names) {
      const bodies = functions(source, name);
      assert.ok(bodies.length, file + ':' + name + ' exists');
      for (const body of bodies) {
        assert.match(body, /require_step_up\(/, file + ':' + name + ' enforces step-up');
        const required = risk === 'very' ? 'VeryRisky' : 'TwoFactor';
        assert.ok(body.includes('StepUpRisk::' + required), file + ':' + name + ' keeps its risk');
        if (risk === 'conditional') assert.ok(body.includes('StepUpRisk::VeryRisky'), name + ' retains privileged risk');
      }
    }
  });
}
test('standard and autonomous entry points do not acquire interactive proof', () => {
  for (const name of ['create_app', 'create_env', 'create_e2e_env', 'create_proposal', 'request_access', 'put_emergency', 'put_app_emergency', 'enroll_device', 'self_renew_device', 'trigger_sync', 'process_rotations_inner']) {
    const bodies = functions(app, name);
    assert.ok(bodies.length, 'app.rs:' + name + ' exists');
    for (const body of bodies) assert.ok(!body.includes('require_step_up('), name);
  }
});
test('path-restricted sessions can obtain proof without opening other auth operations', () => {
  const policy = fs.readFileSync(path.join(root, 'path_policy.rs'), 'utf8');
  const allowed = policy.slice(policy.indexOf('let allowed=matches!'));
  assert.match(allowed, /"POST","\/api\/auth\/logout" \| "\/api\/auth\/step-up\/start" \| "\/api\/auth\/step-up\/verify"/);
  assert.ok(!allowed.includes('"/api/me/totp/setup"'));
});
test('grant consumption and challenge exchange retain atomic predicates', () => {
  const consume = functions(app, 'consume_step_up_grant')[0];
  assert.match(consume, /UPDATE step_up_grants SET used=1 WHERE token_hash=\? AND user_id=\? AND used=0 AND expires_at>\?/);
  assert.match(consume, /risk=\? OR risk='very_risky'/);
  assert.match(consume, /EXISTS \(SELECT 1 FROM sessions s JOIN users/);
  const verify = functions(app, 'step_up_verify')[0];
  assert.match(verify, /batch_checked\(/);
  assert.match(verify, /used=0 AND attempts<5 AND expires_at>\?/);
  assert.match(verify, /INSERT INTO step_up_grants/);
});
