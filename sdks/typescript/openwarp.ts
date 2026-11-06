// OpenWarp TypeScript SDK. No runtime dependencies; uses global fetch and runs
// on Node 22+ (native type stripping) or any browser bundler. The contract is
// ../../openapi.json; scripts/check-openapi.py keeps the spec and server aligned.

export interface OpenWarpOptions {
  /** Instance origin, e.g. https://secrets.example.com */
  host: string;
  /** Session, service, or OAuth access token. */
  token?: string;
  /** Injectable fetch for tests or non-standard runtimes. */
  fetch?: typeof fetch;
}

export class OpenWarpError extends Error {
  status: number;
  body: unknown;
  constructor(status: number, message: string, body: unknown) {
    super(message);
    this.name = "OpenWarpError";
    this.status = status;
    this.body = body;
  }
}

export interface Org { id: string; name: string; ip_allowlist?: string; role?: string }
export interface App { id: string; org_id?: string; name: string; readme?: string; created_at?: number }
export interface Env { id: string; app_id?: string; name: string; mode?: string; restricted?: number; require_approval?: number; created_at?: number }
export interface Secret {
  id: string; key: string; value: string | null; path?: string; comment?: string;
  tags?: string; type?: string; version?: number; updated_at?: number; decrypt_error?: boolean;
}
export interface SecretInput { key: string; value: string; path?: string; comment?: string; tags?: string; type?: "secret" | "sealed" | "config" }
export interface Member { id: string; email: string; role: string; created_at?: number }
export interface ServiceToken { id: string; app_id?: string; env_id?: string; name: string; kind?: string; created_at?: number; created_by?: string }
export interface Integration { id: string; env_id?: string; kind: string; name?: string; created_at?: number }
export interface Lease { id: string; name?: string; value?: string; username?: string; expires_at?: number; type?: string }
export interface Rotation { id: string; env_id?: string; key_name: string; path?: string; interval_secs: number; next_run?: number; enabled?: number }
export interface AuditEntry { id: string; org_id?: string; app_id?: string; env_id?: string; actor?: string; action: string; detail?: string; created_at?: number }
export interface Providers { password: boolean; google: boolean; github: boolean; signups: "open" | "invite" }
export interface Session { token: string; user_id?: string; org_id?: string; public_key?: string; recovery_kit?: string; verification_required?: boolean }
export interface DeployResult { deployed: number; sync_errors: string[] }
export interface CompareResult { only_in_source: string[]; only_in_target: string[]; changed: string[]; same: number }
export interface CloneResult { cloned: number; skipped: number; sync_errors: string[] }
export interface SecretsResult { secrets: Secret[] }
export interface ExportResult { text: string; secrets: Secret[] }
export interface Identity { id: string; org_id?: string; name: string; role?: string; created_at?: number }
export interface IdentityCredentials { id: string; client_id: string; client_secret: string; note?: string }
export interface MachineToken { accessToken: string; expiresIn: number; tokenType: string; identity_id: string }
export interface PkiCertificate { id: string; certificate: string; private_key?: string; ca_certificate?: string }

const encode = (value: string) => encodeURIComponent(value);
const query = (params: Record<string, string | number | boolean | undefined>) => {
  const entries = Object.entries(params).filter(([, v]) => v !== undefined);
  return entries.length ? "?" + entries.map(([k, v]) => `${encode(k)}=${encode(String(v))}`).join("&") : "";
};

export class OpenWarp {
  readonly host: string;
  token: string;
  private http: typeof fetch;

  constructor(options: OpenWarpOptions) {
    this.host = options.host.replace(/\/+$/, "");
    this.token = options.token ?? "";
    const impl = options.fetch ?? globalThis.fetch;
    if (!impl) throw new Error("OpenWarp needs fetch; pass options.fetch on runtimes without it");
    this.http = impl;
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = { Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (this.token) headers["Authorization"] = `Bearer ${this.token}`;
    const response = await this.http(`${this.host}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await response.text();
    const parsed = text ? JSON.parse(text) : null;
    if (!response.ok) {
      const message = parsed && typeof parsed === "object" && "error" in parsed ? String((parsed as { error: unknown }).error) : `HTTP ${response.status}`;
      throw new OpenWarpError(response.status, message, parsed);
    }
    return parsed as T;
  }

  // ---- authentication ----
  register(email: string, password: string) { return this.request<Session>("POST", "/api/auth/register", { email, password }); }
  login(email: string, password: string) {
    return this.request<Session & { mfa_required?: boolean; mfa_token?: string }>("POST", "/api/auth/login", { email, password });
  }
  completeMfa(mfaToken: string, code: string) { return this.request<Session>("POST", "/api/auth/mfa", { mfa_token: mfaToken, code }); }
  me() { return this.request<{ id: string; email: string; pubkey: string }>("GET", "/api/me"); }
  providers() { return this.request<Providers>("GET", "/api/auth/providers"); }
  logout() { return this.request<{ ok: boolean }>("POST", "/api/auth/logout"); }
  forgotPassword(email: string) { return this.request<{ ok: boolean }>("POST", "/api/auth/forgot", { email }); }
  resetPassword(token: string, password: string, options: { recoveryKit?: string; discardE2eKey?: boolean } = {}) {
    return this.request<Session & { e2e_key_replaced?: boolean }>("POST", "/api/auth/reset", {
      token, password, recovery_kit: options.recoveryKit, discard_e2e_key: options.discardE2eKey,
    });
  }
  acceptInvite(token: string, password: string) { return this.request<Session>("POST", "/api/auth/accept-invite", { token, password }); }
  resendVerification(email: string) { return this.request<{ ok: boolean }>("POST", "/api/auth/resend-verification", { email }); }

  // ---- organisations ----
  listOrgs() { return this.request<Org[]>("GET", "/api/orgs"); }
  createOrg(name: string) { return this.request<{ id: string }>("POST", "/api/orgs", { name }); }
  renameOrg(org: string, name: string) { return this.request<{ ok: boolean }>("PATCH", `/api/orgs/${encode(org)}`, { name }); }
  listMembers(org: string) { return this.request<Member[]>("GET", `/api/orgs/${encode(org)}/members`); }
  inviteMember(org: string, email: string, role = "developer") {
    return this.request<{ ok: boolean; added?: boolean; invite_token?: string }>("POST", `/api/orgs/${encode(org)}/members`, { email, role });
  }
  removeMember(org: string, userId: string) { return this.request<{ ok: boolean }>("DELETE", `/api/orgs/${encode(org)}/members/${encode(userId)}`); }
  updateMemberRole(org: string, userId: string, role: string) {
    return this.request<{ ok: boolean }>("PATCH", `/api/orgs/${encode(org)}/members/${encode(userId)}`, { role });
  }
  leaveOrg(org: string) { return this.request<{ ok: boolean }>("POST", `/api/orgs/${encode(org)}/leave`); }
  transferOrg(org: string, userId: string) { return this.request<{ ok: boolean }>("POST", `/api/orgs/${encode(org)}/transfer`, { user_id: userId }); }
  audit(org: string) { return this.request<AuditEntry[]>("GET", `/api/orgs/${encode(org)}/audit`); }
  listRoles(org: string) { return this.request<unknown[]>("GET", `/api/orgs/${encode(org)}/roles`); }
  createRole(org: string, name: string, permissions: string[]) {
    return this.request<unknown>("POST", `/api/orgs/${encode(org)}/roles`, { name, permissions });
  }
  orgSettings(org: string) { return this.request<Record<string, unknown>>("GET", `/api/orgs/${encode(org)}/settings`); }
  updateOrgSettings(org: string, settings: Record<string, unknown>) {
    return this.request<{ ok: boolean }>("PUT", `/api/orgs/${encode(org)}/settings`, settings);
  }
  instance() { return this.request<Record<string, unknown>>("GET", "/api/instance"); }
  setSignups(open: boolean) { return this.request<Record<string, unknown>>("PUT", "/api/instance/signups", { open }); }

  // ---- apps and environments ----
  listApps(org: string) { return this.request<App[]>("GET", `/api/orgs/${encode(org)}/apps`); }
  createApp(org: string, name: string, readme = "") { return this.request<{ id: string }>("POST", `/api/orgs/${encode(org)}/apps`, { name, readme }); }
  renameApp(app: string, name: string) { return this.request<{ ok: boolean }>("PATCH", `/api/apps/${encode(app)}`, { name }); }
  deleteApp(app: string) { return this.request<{ ok: boolean }>("DELETE", `/api/apps/${encode(app)}`); }
  listEnvs(app: string) { return this.request<Env[]>("GET", `/api/apps/${encode(app)}/envs`); }
  createEnv(app: string, name: string) { return this.request<{ id: string }>("POST", `/api/apps/${encode(app)}/envs`, { name }); }
  renameEnv(env: string, name: string) { return this.request<{ ok: boolean }>("PATCH", `/api/envs/${encode(env)}`, { name }); }
  deleteEnv(env: string) { return this.request<{ ok: boolean }>("DELETE", `/api/envs/${encode(env)}`); }
  setEnvPolicy(env: string, policy: { restricted?: boolean; requireApproval?: boolean }) {
    return this.request<{ ok: boolean }>("PUT", `/api/envs/${encode(env)}/policy`, {
      restricted: policy.restricted, require_approval: policy.requireApproval,
    });
  }

  // ---- secrets ----
  listSecrets(env: string) { return this.request<SecretsResult>("GET", `/api/envs/${encode(env)}/secrets`); }
  deploySecrets(env: string, secrets: SecretInput[]) { return this.request<DeployResult>("PUT", `/api/envs/${encode(env)}/secrets`, { secrets }); }
  exportEnv(env: string) { return this.request<ExportResult>("GET", `/api/envs/${encode(env)}/export`); }
  importEnv(env: string, text: string) { return this.request<DeployResult>("POST", `/api/envs/${encode(env)}/import`, { text }); }
  compareEnvs(env: string, other: string) { return this.request<CompareResult>("GET", `/api/envs/${encode(env)}/compare${query({ other })}`); }
  cloneEnv(env: string, targetEnvId: string, overwrite = false) {
    return this.request<CloneResult>("POST", `/api/envs/${encode(env)}/clone`, { target_env_id: targetEnvId, overwrite });
  }
  rotateSecret(env: string, key: string, options: { value?: string; path?: string } = {}) {
    return this.request<{ key: string; value: string; secret_id: string }>("POST", `/api/envs/${encode(env)}/rotate`, { key, ...options });
  }
  restorePoint(env: string, timestamp?: number) {
    return this.request<{ restored: number }>("POST", `/api/envs/${encode(env)}/restore-point`, { timestamp });
  }
  deleteSecret(secret: string) { return this.request<{ ok: boolean }>("DELETE", `/api/secrets/${encode(secret)}`); }
  secretHistory(secret: string) {
    return this.request<Array<{ version: number; value: string; created_at: number; created_by: string }>>("GET", `/api/secrets/${encode(secret)}/history`);
  }
  restoreSecret(secret: string, version: number) {
    return this.request<{ ok: boolean; version: number }>("POST", `/api/secrets/${encode(secret)}/restore/${version}`);
  }
  setOverride(secret: string, value: string) {
    return this.request<{ ok: boolean }>("POST", `/api/secrets/${encode(secret)}/override`, { secrets: [{ key: "x", value }] });
  }

  // ---- service tokens ----
  listTokens(app: string) { return this.request<ServiceToken[]>("GET", `/api/apps/${encode(app)}/tokens`); }
  createToken(app: string, name = "token", envId = "") {
    return this.request<{ id: string; token: string }>("POST", `/api/apps/${encode(app)}/tokens`, { name, env_id: envId });
  }
  revokeToken(tokenId: string) { return this.request<{ revoked: string }>("DELETE", `/api/tokens/${encode(tokenId)}`); }

  // ---- integrations ----
  listIntegrations(env: string) { return this.request<Integration[]>("GET", `/api/envs/${encode(env)}/integrations`); }
  createIntegration(env: string, kind: string, config: Record<string, unknown>, name = kind) {
    return this.request<{ id: string }>("POST", `/api/envs/${encode(env)}/integrations`, { kind, name, config });
  }
  updateIntegration(id: string, changes: { kind?: string; name?: string; config?: Record<string, unknown> }) {
    return this.request<{ ok: boolean }>("PATCH", `/api/integrations/${encode(id)}`, changes);
  }
  deleteIntegration(id: string) { return this.request<{ deleted: string }>("DELETE", `/api/integrations/${encode(id)}`); }
  syncIntegration(id: string) { return this.request<{ ok: boolean; detail: string }>("POST", `/api/integrations/${encode(id)}/sync`); }
  testIntegration(id: string) { return this.request<{ ok: boolean; detail: string }>("POST", `/api/integrations/${encode(id)}/test`); }

  // ---- dynamic leases and rotations ----
  listLeases(env: string) { return this.request<Lease[]>("GET", `/api/envs/${encode(env)}/dynamic`); }
  createLease(env: string, options: { name?: string; ttlSecs?: number; type?: string; config?: Record<string, unknown> } = {}) {
    return this.request<Lease>("POST", `/api/envs/${encode(env)}/dynamic`, {
      name: options.name, ttl_secs: options.ttlSecs, type: options.type, config: options.config,
    });
  }
  revokeLease(lease: string) { return this.request<{ revoked: string }>("DELETE", `/api/leases/${encode(lease)}`); }
  renewLease(lease: string, ttlSecs?: number) { return this.request<Lease>("POST", `/api/leases/${encode(lease)}/renew`, { ttl_secs: ttlSecs }); }
  listRotations(env: string) { return this.request<Rotation[]>("GET", `/api/envs/${encode(env)}/rotations`); }
  createRotation(env: string, key: string, intervalSecs: number, path = "/") {
    return this.request<{ id: string; next_run: number }>("POST", `/api/envs/${encode(env)}/rotations`, { key, interval_secs: intervalSecs, path });
  }
  deleteRotation(id: string) { return this.request<{ deleted: string }>("DELETE", `/api/rotations/${encode(id)}`); }

  // ---- machine identities ----
  listIdentities(org: string) { return this.request<Identity[]>("GET", `/api/orgs/${encode(org)}/identities`); }
  createIdentity(org: string, name: string, role = "developer") {
    return this.request<IdentityCredentials>("POST", `/api/orgs/${encode(org)}/identities`, { name, role });
  }
  deleteIdentity(org: string, id: string) { return this.request<{ ok: boolean }>("DELETE", `/api/orgs/${encode(org)}/identities/${encode(id)}`); }
  rotateIdentity(org: string, id: string) {
    return this.request<IdentityCredentials>("POST", `/api/orgs/${encode(org)}/identities/${encode(id)}/rotate`);
  }
  machineLogin(clientId: string, clientSecret: string) {
    return this.request<MachineToken>("POST", "/api/v1/machine/auth/universal/login", { client_id: clientId, client_secret: clientSecret });
  }

  // ---- sharing and search ----
  createLockbox(text: string) { return this.request<{ id: string; key: string; url: string }>("POST", "/api/lockbox", { text }); }
  openLockbox(id: string, key: string) {
    // The API expects the key in a header; fetch directly rather than through request().
    return this.http(`${this.host}/api/lockbox/${encode(id)}`, { headers: { "x-lockbox-key": key, Accept: "application/json" } })
      .then(async (r) => { const body = await r.json(); if (!r.ok) throw new OpenWarpError(r.status, body?.error ?? `HTTP ${r.status}`, body); return body as { value: string }; });
  }
  search(q: string) { return this.request<{ results: Array<{ app: string; env: string; key: string; path: string }> }>("GET", `/api/search${query({ q })}`); }
}
