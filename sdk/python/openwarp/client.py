"""Standard-library client for the OpenWarp HTTP API."""

import json
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


class OpenWarpError(Exception):
    """An HTTP, transport, or response decoding failure (status 0 for transport)."""

    def __init__(self, status, message, body):
        self.status = status
        self.message = message
        self.body = body
        super().__init__(f"OpenWarp ({status}): {message}")


class OpenWarp:
    def __init__(self, base_url, token, timeout=30):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    @staticmethod
    def _segment(value):
        return quote(str(value), safe="")

    def _request(self, method, path, body=None):
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = Request(self.base_url + path, data=data, headers=headers, method=method)
        try:
            with urlopen(request, timeout=self.timeout) as response:
                status = response.status
                raw = response.read().decode("utf-8", errors="replace")
        except HTTPError as exc:
            with exc:
                raw = exc.read().decode("utf-8", errors="replace")
            message = raw or exc.reason
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    message = parsed.get("error") or parsed.get("message") or message
            except ValueError:
                pass
            raise OpenWarpError(exc.code, str(message), raw) from exc
        except (URLError, OSError) as exc:
            raise OpenWarpError(0, str(exc), "") from exc
        if not raw:
            return None
        try:
            return json.loads(raw)
        except ValueError as exc:
            raise OpenWarpError(status, "Invalid JSON response", raw) from exc

    def me(self):
        return self._request("GET", "/api/me")

    def orgs(self):
        return self._request("GET", "/api/orgs")

    def apps(self, org):
        return self._request("GET", f"/api/orgs/{self._segment(org)}/apps")

    def envs(self, app):
        return self._request("GET", f"/api/apps/{self._segment(app)}/envs")

    def secrets(self, env):
        return self._request("GET", f"/api/envs/{self._segment(env)}/secrets")["secrets"]

    def get_secret(self, env, key):
        """Return the first case-insensitive key match, or raise a 404 error."""
        for secret in self.secrets(env):
            if secret["key"].casefold() == key.casefold():
                return secret
        raise OpenWarpError(404, f"Secret not found: {key}", "")

    def set_secret(self, env, key, value, path="/", type="secret", comment=""):
        return self._request("PUT", f"/api/envs/{self._segment(env)}/secrets", {
            "secrets": [{"key": key, "value": value, "path": path,
                         "type": type, "comment": comment, "tags": ""}]
        })

    def delete_secret(self, env, key):
        secret = self.get_secret(env, key)
        return self._request("DELETE", f"/api/secrets/{self._segment(secret['id'])}")

    def export(self, env):
        return self._request("GET", f"/api/envs/{self._segment(env)}/export")

    def leases(self, env):
        return self._request("GET", f"/api/envs/{self._segment(env)}/dynamic")

    def create_lease(self, env, name, ttl_secs=3600):
        return self._request("POST", f"/api/envs/{self._segment(env)}/dynamic",
                             {"name": name, "ttl_secs": ttl_secs})

    def audit(self, org):
        return self._request("GET", f"/api/orgs/{self._segment(org)}/audit")
