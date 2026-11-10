export interface Org { id: string; name: string; role?: string }
export interface App { id: string; org_id: string; name: string }
export interface Env { id: string; app_id: string; name: string }
export interface Secret {
  id: string;
  key: string;
  value: string;
  path: string;
  type: string;
  comment: string;
  tags: string;
  version?: number;
}
export interface Lease {
  id: string;
  expires_at: number;
  name?: string;
  value?: string;
  username?: string;
  password?: string;
  type?: string;
}
export interface LeaseInput {
  name?: string;
  ttl_secs?: number;
  type?: string;
  config?: Record<string, unknown>;
}
export interface DeployResult { deployed: number; sync_errors: unknown[] }
export interface ExportResult { text: string; secrets: Secret[] }

export class OpenWarpError extends Error {
  constructor(public readonly status: number, message: string, public readonly body: unknown) {
    super(message);
    this.name = "OpenWarpError";
  }
}

export class OpenWarpClient {
  private readonly baseUrl: string;

  constructor(baseUrl: string, private readonly token: string, private readonly fetchImpl: typeof fetch = fetch) {
    const url = new URL(baseUrl);
    if (!["http:", "https:"].includes(url.protocol) || baseUrl.includes("?") || baseUrl.includes("#") || url.username || url.password) {
      throw new TypeError("baseUrl must be an HTTP(S) URL without credentials, query, or fragment");
    }
    this.baseUrl = url.toString().replace(/\/+$/, "");
  }

  api<T = unknown>(method: string, segments: string[], body?: unknown, query?: Record<string, string>, stepUp?: string): Promise<T> {
    if (stepUp !== undefined && (typeof stepUp !== "string" || !stepUp.length || stepUp.length > 512 || /[^\x20-\x7e]/.test(stepUp))) throw new TypeError("Invalid step-up grant");
    if (!["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].includes(method)) throw new TypeError("Unsupported HTTP method");
    if (!Array.isArray(segments) || !segments.length) throw new TypeError("Expected non-empty path segments");
    for (const segment of segments) {
      if (typeof segment !== "string" || !segment) throw new TypeError("Expected non-empty path segments");
      let decoded = segment;
      for (let depth = 0; depth <= segment.length; depth++) {
        if (decoded.split("/").some(part => part === "." || part === "..") || /[\\\\\x00-\x1f\x7f]/.test(decoded) || decoded.includes("://") || decoded.startsWith("//")) throw new TypeError("Unsafe path segment");
        const next = decodeURIComponent(decoded);
        if (next === decoded) break;
        decoded = next;
      }
    }
    return this.request(method, segments, body, query, stepUp);
  }

  private async request<T>(method: string, segments: string[], body?: unknown, query?: Record<string, string>, stepUp?: string): Promise<T> {
    // Dot segments are normalized by URL parsers even when percent-encoded.
    if (segments.some(s => s === "." || s === "..")) throw new TypeError("Dot path segments are not supported");
    const search = query ? new URLSearchParams(query).toString() : "";
    const response = await this.fetchImpl(`${this.baseUrl}/api/${segments.map(encodeURIComponent).join("/")}${search ? "?" + search : ""}`, {
      method,
      redirect: "error",
      headers: { Authorization: `Bearer ${this.token}`, Accept: "application/json", ...(body === undefined ? {} : { "Content-Type": "application/json" }), ...(stepUp === undefined ? {} : { "X-OpenWarp-Step-Up": stepUp }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const text = await response.text();
    let data: unknown = text || undefined;
    if (text) {
      try { data = JSON.parse(text); } catch (error) { if (response.ok) throw error; }
    }
    if (!response.ok) {
      const fields = data && typeof data === "object" ? data as Record<string, unknown> : {};
      const message = typeof fields.error === "string" ? fields.error : typeof fields.message === "string" ? fields.message : response.statusText || `HTTP ${response.status}`;
      throw new OpenWarpError(response.status, message, data);
    }
    return data as T;
  }

  me(): Promise<Record<string, unknown>> { return this.request("GET", ["me"]); }
  orgs(): Promise<Org[]> { return this.request("GET", ["orgs"]); }
  apps(org: string): Promise<App[]> { return this.request("GET", ["orgs", org, "apps"]); }
  envs(app: string): Promise<Env[]> { return this.request("GET", ["apps", app, "envs"]); }
  async secrets(env: string): Promise<Secret[]> {
    return (await this.request<{ secrets: Secret[] }>("GET", ["envs", env, "secrets"])).secrets;
  }
  async getSecret(env: string, key: string): Promise<Secret | undefined> {
    const matches = (await this.secrets(env)).filter(s => s.key.toUpperCase() === key.toUpperCase());
    if (matches.length > 1) throw new OpenWarpError(409, "Key exists at multiple paths", undefined);
    return matches[0];
  }
  setSecret(env: string, key: string, value: string, path = "/", type = "secret", comment = ""): Promise<DeployResult> {
    return this.request("PUT", ["envs", env, "secrets"], { secrets: [{ key, value, path, type, comment, tags: "" }] });
  }
  async deleteSecret(env: string, key: string): Promise<void> {
    const secret = await this.getSecret(env, key);
    if (secret) await this.request("DELETE", ["secrets", secret.id]);
  }
  export(env: string): Promise<ExportResult> { return this.request("GET", ["envs", env, "export"]); }
  leases(env: string): Promise<Lease[]> { return this.request("GET", ["envs", env, "dynamic"]); }
  createLease(env: string, input: LeaseInput = {}): Promise<Lease> { return this.request("POST", ["envs", env, "dynamic"], input); }
  audit(org: string): Promise<Record<string, unknown>[]> { return this.request("GET", ["orgs", org, "audit"]); }
}
