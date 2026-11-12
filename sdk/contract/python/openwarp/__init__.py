"""OpenWarp Python SDK. Standard library only.

The contract is ../../../openapi.json; ``scripts/check-openapi.py`` keeps the spec
and the server routes aligned. Advanced surfaces (OAuth authorization, MCP,
SCIM, PKI) are intentionally not exposed here.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

__all__ = ["Client", "OpenWarpError"]


class OpenWarpError(Exception):
    """A non-2xx answer from the API, carrying the parsed body."""

    def __init__(self, status: int, message: str, body: Any = None) -> None:
        super().__init__(message)
        self.status = status
        self.body = body


def _quote(value: str) -> str:
    return urllib.parse.quote(str(value), safe="")


def _query(**params: Any) -> str:
    pairs = [(k, v) for k, v in params.items() if v is not None]
    if not pairs:
        return ""
    return "?" + urllib.parse.urlencode(pairs)


class Client:
    def __init__(self, host: str, token: Optional[str] = None, timeout: float = 30.0) -> None:
        self.host = host.rstrip("/")
        self.token = token or ""
        self.timeout = timeout

    def _request(self, method: str, path: str, body: Any = None) -> Any:
        headers = {"Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(self.host + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as error:
            raw = error.read()
            try:
                parsed = json.loads(raw) if raw else None
            except json.JSONDecodeError:
                parsed = raw.decode(errors="replace")
            message = parsed.get("error") if isinstance(parsed, dict) else f"HTTP {error.code}"
            raise OpenWarpError(error.code, str(message), parsed) from None

    # ---- authentication ----
    def register(self, email: str, password: str) -> dict:
        return self._request("POST", "/api/auth/register", {"email": email, "password": password})

    def login(self, email: str, password: str) -> dict:
        return self._request("POST", "/api/auth/login", {"email": email, "password": password})

    def complete_mfa(self, mfa_token: str, code: str) -> dict:
        return self._request("POST", "/api/auth/mfa", {"mfa_token": mfa_token, "code": code})

    def me(self) -> dict:
        return self._request("GET", "/api/me")

    def providers(self) -> dict:
        return self._request("GET", "/api/auth/providers")

    def logout(self) -> dict:
        return self._request("POST", "/api/auth/logout")

    def forgot_password(self, email: str) -> dict:
        return self._request("POST", "/api/auth/forgot", {"email": email})

    def reset_password(self, token: str, password: str, recovery_kit: Optional[str] = None, discard_e2e_key: bool = False) -> dict:
        return self._request("POST", "/api/auth/reset", {
            "token": token, "password": password, "recovery_kit": recovery_kit, "discard_e2e_key": discard_e2e_key,
        })

    def accept_invite(self, token: str, password: str) -> dict:
        return self._request("POST", "/api/auth/accept-invite", {"token": token, "password": password})

    def resend_verification(self, email: str) -> dict:
        return self._request("POST", "/api/auth/resend-verification", {"email": email})

    # ---- organisations ----
    def list_orgs(self) -> list:
        return self._request("GET", "/api/orgs")

    def create_org(self, name: str) -> dict:
        return self._request("POST", "/api/orgs", {"name": name})

    def rename_org(self, org: str, name: str) -> dict:
        return self._request("PATCH", f"/api/orgs/{_quote(org)}", {"name": name})

    def list_members(self, org: str) -> list:
        return self._request("GET", f"/api/orgs/{_quote(org)}/members")

    def invite_member(self, org: str, email: str, role: str = "developer") -> dict:
        return self._request("POST", f"/api/orgs/{_quote(org)}/members", {"email": email, "role": role})

    def remove_member(self, org: str, user_id: str) -> dict:
        return self._request("DELETE", f"/api/orgs/{_quote(org)}/members/{_quote(user_id)}")

    def update_member_role(self, org: str, user_id: str, role: str) -> dict:
        return self._request("PATCH", f"/api/orgs/{_quote(org)}/members/{_quote(user_id)}", {"role": role})

    def leave_org(self, org: str) -> dict:
        return self._request("POST", f"/api/orgs/{_quote(org)}/leave")

    def transfer_org(self, org: str, user_id: str) -> dict:
        return self._request("POST", f"/api/orgs/{_quote(org)}/transfer", {"user_id": user_id})

    def audit(self, org: str) -> list:
        return self._request("GET", f"/api/orgs/{_quote(org)}/audit")

    def list_roles(self, org: str) -> list:
        return self._request("GET", f"/api/orgs/{_quote(org)}/roles")

    def create_role(self, org: str, name: str, permissions: list[str]) -> dict:
        return self._request("POST", f"/api/orgs/{_quote(org)}/roles", {"name": name, "permissions": permissions})

    def org_settings(self, org: str) -> dict:
        return self._request("GET", f"/api/orgs/{_quote(org)}/settings")

    def update_org_settings(self, org: str, settings: dict) -> dict:
        return self._request("PUT", f"/api/orgs/{_quote(org)}/settings", settings)

    def instance(self) -> dict:
        return self._request("GET", "/api/instance")

    def set_signups(self, open: bool) -> dict:
        return self._request("PUT", "/api/instance/signups", {"open": open})

    # ---- apps and environments ----
    def list_apps(self, org: str) -> list:
        return self._request("GET", f"/api/orgs/{_quote(org)}/apps")

    def create_app(self, org: str, name: str, readme: str = "") -> dict:
        return self._request("POST", f"/api/orgs/{_quote(org)}/apps", {"name": name, "readme": readme})

    def rename_app(self, app: str, name: str) -> dict:
        return self._request("PATCH", f"/api/apps/{_quote(app)}", {"name": name})

    def delete_app(self, app: str) -> dict:
        return self._request("DELETE", f"/api/apps/{_quote(app)}")

    def list_envs(self, app: str) -> list:
        return self._request("GET", f"/api/apps/{_quote(app)}/envs")

    def create_env(self, app: str, name: str) -> dict:
        return self._request("POST", f"/api/apps/{_quote(app)}/envs", {"name": name})

    def rename_env(self, env: str, name: str) -> dict:
        return self._request("PATCH", f"/api/envs/{_quote(env)}", {"name": name})

    def delete_env(self, env: str) -> dict:
        return self._request("DELETE", f"/api/envs/{_quote(env)}")

    def set_env_policy(self, env: str, restricted: Optional[bool] = None, require_approval: Optional[bool] = None) -> dict:
        return self._request("PUT", f"/api/envs/{_quote(env)}/policy", {
            "restricted": restricted, "require_approval": require_approval,
        })

    # ---- secrets ----
    def list_secrets(self, env: str) -> dict:
        return self._request("GET", f"/api/envs/{_quote(env)}/secrets")

    def deploy_secrets(self, env: str, secrets: list[dict]) -> dict:
        return self._request("PUT", f"/api/envs/{_quote(env)}/secrets", {"secrets": secrets})

    def export_env(self, env: str) -> dict:
        return self._request("GET", f"/api/envs/{_quote(env)}/export")

    def import_env(self, env: str, text: str) -> dict:
        return self._request("POST", f"/api/envs/{_quote(env)}/import", {"text": text})

    def compare_envs(self, env: str, other: str) -> dict:
        return self._request("GET", f"/api/envs/{_quote(env)}/compare{_query(other=other)}")

    def clone_env(self, env: str, target_env_id: str, overwrite: bool = False) -> dict:
        return self._request("POST", f"/api/envs/{_quote(env)}/clone", {"target_env_id": target_env_id, "overwrite": overwrite})

    def rotate_secret(self, env: str, key: str, value: Optional[str] = None, path: Optional[str] = None) -> dict:
        return self._request("POST", f"/api/envs/{_quote(env)}/rotate", {"key": key, "value": value, "path": path})

    def restore_point(self, env: str, timestamp: Optional[int] = None) -> dict:
        return self._request("POST", f"/api/envs/{_quote(env)}/restore-point", {"timestamp": timestamp})

    def delete_secret(self, secret: str) -> dict:
        return self._request("DELETE", f"/api/secrets/{_quote(secret)}")

    def secret_history(self, secret: str) -> list:
        return self._request("GET", f"/api/secrets/{_quote(secret)}/history")

    def restore_secret(self, secret: str, version: int) -> dict:
        return self._request("POST", f"/api/secrets/{_quote(secret)}/restore/{version}")

    def set_override(self, secret: str, value: str) -> dict:
        return self._request("POST", f"/api/secrets/{_quote(secret)}/override", {"secrets": [{"key": "x", "value": value}]})

    # ---- service tokens ----
    def list_tokens(self, app: str) -> list:
        return self._request("GET", f"/api/apps/{_quote(app)}/tokens")

    def create_token(self, app: str, name: str = "token", env_id: str = "") -> dict:
        return self._request("POST", f"/api/apps/{_quote(app)}/tokens", {"name": name, "env_id": env_id})

    def revoke_token(self, token_id: str) -> dict:
        return self._request("DELETE", f"/api/tokens/{_quote(token_id)}")

    # ---- integrations ----
    def list_integrations(self, env: str) -> list:
        return self._request("GET", f"/api/envs/{_quote(env)}/integrations")

    def create_integration(self, env: str, kind: str, config: dict, name: Optional[str] = None) -> dict:
        return self._request("POST", f"/api/envs/{_quote(env)}/integrations", {"kind": kind, "name": name or kind, "config": config})

    def update_integration(self, integration: str, changes: dict) -> dict:
        return self._request("PATCH", f"/api/integrations/{_quote(integration)}", changes)

    def delete_integration(self, integration: str) -> dict:
        return self._request("DELETE", f"/api/integrations/{_quote(integration)}")

    def sync_integration(self, integration: str) -> dict:
        return self._request("POST", f"/api/integrations/{_quote(integration)}/sync")

    def test_integration(self, integration: str) -> dict:
        return self._request("POST", f"/api/integrations/{_quote(integration)}/test")

    # ---- dynamic leases and rotations ----
    def list_leases(self, env: str) -> list:
        return self._request("GET", f"/api/envs/{_quote(env)}/dynamic")

    def create_lease(self, env: str, name: Optional[str] = None, ttl_secs: Optional[int] = None,
                     type: Optional[str] = None, config: Optional[dict] = None) -> dict:
        return self._request("POST", f"/api/envs/{_quote(env)}/dynamic", {
            "name": name, "ttl_secs": ttl_secs, "type": type, "config": config,
        })

    def revoke_lease(self, lease: str) -> dict:
        return self._request("DELETE", f"/api/leases/{_quote(lease)}")

    def renew_lease(self, lease: str, ttl_secs: Optional[int] = None) -> dict:
        return self._request("POST", f"/api/leases/{_quote(lease)}/renew", {"ttl_secs": ttl_secs})

    def list_rotations(self, env: str) -> list:
        return self._request("GET", f"/api/envs/{_quote(env)}/rotations")

    def create_rotation(self, env: str, key: str, interval_secs: int, path: str = "/") -> dict:
        return self._request("POST", f"/api/envs/{_quote(env)}/rotations", {"key": key, "interval_secs": interval_secs, "path": path})

    def delete_rotation(self, rotation: str) -> dict:
        return self._request("DELETE", f"/api/rotations/{_quote(rotation)}")

    # ---- machine identities ----
    def list_identities(self, org: str) -> list:
        return self._request("GET", f"/api/orgs/{_quote(org)}/identities")

    def create_identity(self, org: str, name: str, role: str = "developer") -> dict:
        return self._request("POST", f"/api/orgs/{_quote(org)}/identities", {"name": name, "role": role})

    def delete_identity(self, org: str, identity: str) -> dict:
        return self._request("DELETE", f"/api/orgs/{_quote(org)}/identities/{_quote(identity)}")

    def rotate_identity(self, org: str, identity: str) -> dict:
        return self._request("POST", f"/api/orgs/{_quote(org)}/identities/{_quote(identity)}/rotate")

    def machine_login(self, client_id: str, client_secret: str) -> dict:
        return self._request("POST", "/api/v1/machine/auth/universal/login", {"client_id": client_id, "client_secret": client_secret})

    # ---- sharing and search ----
    def create_lockbox(self, text: str) -> dict:
        return self._request("POST", "/api/lockbox", {"text": text})

    def open_lockbox(self, box_id: str, key: str) -> dict:
        request = urllib.request.Request(
            f"{self.host}/api/lockbox/{_quote(box_id)}",
            headers={"x-lockbox-key": key, "Accept": "application/json"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as error:
            raw = error.read()
            parsed = json.loads(raw) if raw else None
            raise OpenWarpError(error.code, str((parsed or {}).get("error", error.code)), parsed) from None

    def search(self, q: str) -> dict:
        return self._request("GET", f"/api/search{_query(q=q)}")
